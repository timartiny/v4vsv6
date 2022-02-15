package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/alexflint/go-arg"
	"github.com/timartiny/v4vsv6"
)

var (
	infoLogger  *log.Logger
	errorLogger *log.Logger
)

type MergeResultsFlags struct {
	DataFolder string `arg:"--data-folder,required" help:"(Required) The folder to read data from and write to" json:"data_folder"`
	DateString string `arg:"--date-string,required" help:"(Required) The date string present in data files" json:"date_string"`
	Verbose    bool   `arg:"--verbose,-v" help:"Whether to add extra printing for debugging" json:"verbose"`
}

func setupArgs() MergeResultsFlags {
	var ret MergeResultsFlags
	arg.MustParse(&ret)

	return ret
}

//indexDRRDay will read the given day's domain-resolver-results JSON file and
//get the number of bytes into the file each domain-resolver ip-requested record
//result is for future lookups
func indexDRRDay(
	drrIndex map[string]uint,
	args MergeResultsFlags,
	day int,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	drrFileName := filepath.Join(
		args.DataFolder,
		fmt.Sprintf("%s-domain-resolver-results_day%d.json", args.DateString, day),
	)
	infoLogger.Printf("Indexing %s\n", drrFileName)
	drrFile, err := os.Open(drrFileName)
	if err != nil {
		errorLogger.Printf("Error opening file: %s, %v\n", drrFileName, err)
	}
	defer drrFile.Close()
	drrReader := bufio.NewReader(drrFile)
	var totalBytes uint

	for {
		drrBytes, readErr := drrReader.ReadBytes('\n')
		if readErr != nil && readErr != io.EOF {
			errorLogger.Fatalf(
				"Got an unexpected error reading bytes reading from %s: %v\n",
				drrFileName,
				readErr,
			)
		}
		// possible that the last line has \n, so this last read is empty
		if len(drrBytes) == 0 {
			break
		}
		var drr v4vsv6.DomainResolverResult
		err = json.Unmarshal(drrBytes, &drr)
		if err != nil {
			errorLogger.Printf(
				"Error unmarshaling drr bytes from %s: %v\n", drrFileName, err,
			)
			errorLogger.Printf(
				"Total bytes read: %d, current length of bytes: %d\n",
				totalBytes,
				len(drrBytes),
			)
			errorLogger.Fatalf(
				"Bytes that failed to unmarshal (as string): %s\n",
				string(drrBytes),
			)
		}
		key := fmt.Sprintf(
			"%s-%s-%s", drr.Domain, drr.ResolverIP, drr.RequestedAddressType,
		)
		drrIndex[key] = totalBytes
		totalBytes += uint(len(drrBytes))

		if readErr == io.EOF {
			break
		}
	}
	infoLogger.Printf("Done indexing day %d\n", day)
}

// consolidateResults will loop through day 1's results and look up the
// corresponding day2 and day3 results (if applicable) then write the combined
// results to the master file
func consolidateResults(
	drrDay2Index, drrDay3Index map[string]uint,
	args MergeResultsFlags,
) {
	day1FileName := filepath.Join(
		args.DataFolder,
		fmt.Sprintf("%s-domain-resolver-results_day1.json", args.DateString),
	)
	day1File, err := os.Open(day1FileName)
	if err != nil {
		errorLogger.Printf("Error opening file: %s, %v\n", day1FileName, err)
	}
	defer day1File.Close()
	day2FileName := filepath.Join(
		args.DataFolder,
		fmt.Sprintf("%s-domain-resolver-results_day2.json", args.DateString),
	)
	day2File, err := os.Open(day2FileName)
	if err != nil {
		errorLogger.Printf("Error opening file: %s, %v\n", day2FileName, err)
	}
	defer day2File.Close()
	day3FileName := filepath.Join(
		args.DataFolder,
		fmt.Sprintf("%s-domain-resolver-results_day3.json", args.DateString),
	)
	day3File, err := os.Open(day3FileName)
	if err != nil {
		errorLogger.Printf("Error opening file: %s, %v\n", day3FileName, err)
	}
	defer day3File.Close()

	masterDRRFileName := filepath.Join(
		args.DataFolder,
		fmt.Sprintf("%s-domain-resolver-results.json", args.DateString),
	)
	masterDRRFile, err := os.Create(masterDRRFileName)
	if err != nil {
		errorLogger.Printf(
			"Error creating file: %s, %v\n",
			masterDRRFileName,
			err,
		)
	}
	defer masterDRRFile.Close()

	day1Scanner := bufio.NewScanner(day1File)
	day2Reader := bufio.NewReader(day2File)
	day3Reader := bufio.NewReader(day3File)

	infoLogger.Printf("Reading through %s\n", day1FileName)
	infoLogger.Printf("And writing to %s\n", masterDRRFileName)
	var numLines int
	nextVerboseTime := time.Now().Add(30 * time.Second)
	for day1Scanner.Scan() {
		line := day1Scanner.Text()
		numLines++
		if args.Verbose && time.Now().After(nextVerboseTime) {
			infoLogger.Printf("Read in %d lines of %s\n", numLines, day1FileName)
			nextVerboseTime = time.Now().Add(30 * time.Second)
		}
		var day1DRR, day2DRR, day3DRR v4vsv6.DomainResolverResult
		err := json.Unmarshal([]byte(line), &day1DRR)
		if err != nil {
			errorLogger.Printf(
				"Error unmarshaling following bytes (as string): %s\n", line,
			)
			errorLogger.Fatalf("Unmarshal Error: %v\n", err)
		}
		key := fmt.Sprintf(
			"%s-%s-%s",
			day1DRR.Domain,
			day1DRR.ResolverIP,
			day1DRR.RequestedAddressType,
		)
		if day2ByteCount, day2OK := drrDay2Index[key]; day2OK {
			// day2 data is present as well, so we add it to the day1 drr
			day2Reader.Discard(int(day2ByteCount))
			day2Bytes, err := day2Reader.ReadBytes('\n')
			if err != nil {
				errorLogger.Fatalf(
					"Error reading bytes after Discard: %v\n", err,
				)
			}
			err = json.Unmarshal(day2Bytes, &day2DRR)
			if err != nil {
				errorLogger.Printf(
					"Error unmarshaling following bytes (as string): %s\n",
					string(day2Bytes),
				)
				errorLogger.Fatalf("Unmarshal Error: %v\n", err)
			}

			if day1DRR.Domain != day2DRR.Domain ||
				day1DRR.ResolverIP != day2DRR.ResolverIP ||
				day1DRR.RequestedAddressType != day2DRR.RequestedAddressType {
				errorLogger.Fatalf(
					"Got the incorrect day2 drr\nDay 1: %+v\nDay2: %+v\n",
					day1DRR,
					day2DRR,
				)
			}

			// actually merge data finally
			day1DRR.Day2Results = day2DRR.Day2Results
			// since day2 exists day 1 must have censored, so update the
			// requests censorship to be day 3s

			// this can be uncommented after feb-07 run

			// if !day1DRR.CensoredQuery {
			// 	errorLogger.Printf(
			// 		"Day1DRR wasn't censored, why was it in day2?: %+v\n",
			// 		day1DRR,
			// 	)
			// 	// this can be changed to Fatalf on runs after feb-07
			// 	errorLogger.Printf("day2drr: %+v\n", day2DRR)
			// }
			day1DRR.CensoredQuery = day2DRR.CensoredQuery

			day2File.Seek(0, io.SeekStart)
			day2Reader.Reset(day2File)
		} else {
			// here we didn't get anything in day2 so we confirm we get nothing
			// in day 3
			if _, day3OK := drrDay3Index[key]; day3OK {
				errorLogger.Fatalf(
					"Found %s in day 3 index but NOT in the day 2 index\n", key,
				)
			}
		}

		if day3ByteCount, day3OK := drrDay3Index[key]; day3OK {
			// day3 data is present as well, so we add it to the day1 drr
			day3Reader.Discard(int(day3ByteCount))
			day3Bytes, err := day3Reader.ReadBytes('\n')
			if err != nil {
				errorLogger.Fatalf(
					"Error reading bytes after Discard: %v\n", err,
				)
			}
			err = json.Unmarshal(day3Bytes, &day3DRR)
			if err != nil {
				errorLogger.Printf(
					"Error unmarshaling following bytes (as string): %s\n",
					string(day3Bytes),
				)
				errorLogger.Fatalf("Unmarshal Error: %v\n", err)
			}

			if day1DRR.Domain != day3DRR.Domain ||
				day1DRR.ResolverIP != day3DRR.ResolverIP ||
				day1DRR.RequestedAddressType != day3DRR.RequestedAddressType {
				errorLogger.Fatalf(
					"Got the incorrect day3 drr\nDay 1: %+v\nDay3: %+v\n",
					day1DRR,
					day3DRR,
				)
			}

			// actually merge data finally
			day1DRR.Day3Results = day3DRR.Day3Results
			// since day3 exists day 1 and day2 must have censored, so update
			// the requests censorship to be day 3s

			// this can be uncommented on runs after feb-07

			// if !day1DRR.CensoredQuery {
			// 	errorLogger.Fatalf(
			// 		"Day1DRR wasn't censored, why was it in day3?: %+v\n",
			// 		day1DRR,
			// 	)
			// }
			day1DRR.CensoredQuery = day3DRR.CensoredQuery

			day3File.Seek(0, io.SeekStart)
			day3Reader.Reset(day3File)
		}

		// now we have all the data together, so write it!
		bs, err := json.Marshal(day1DRR)
		if err != nil {
			errorLogger.Fatalf(
				"Error marshaling day1DRR: %+v, %v\n", day1DRR, err,
			)
		}
		_, err = masterDRRFile.Write(bs)
		if err != nil {
			errorLogger.Fatalf(
				"Error writing to file: %s, %v\n", masterDRRFileName, err,
			)
		}
		_, err = masterDRRFile.WriteString("\n")
		if err != nil {
			errorLogger.Fatalf(
				"Error writing newline to file: %v\n", err,
			)
		}
	}
}

func main() {
	infoLogger = log.New(
		os.Stderr,
		"INFO: ",
		log.Ldate|log.Ltime|log.Lshortfile,
	)
	errorLogger = log.New(
		os.Stderr,
		"ERROR: ",
		log.Ldate|log.Ltime|log.Lshortfile,
	)
	drrDay2Index := make(map[string]uint)
	drrDay3Index := make(map[string]uint)
	var indexWG sync.WaitGroup
	args := setupArgs()

	// index day2, day3
	indexWG.Add(1)
	go indexDRRDay(drrDay2Index, args, 2, &indexWG)
	indexWG.Add(1)
	go indexDRRDay(drrDay3Index, args, 3, &indexWG)

	infoLogger.Println("Waiting for day 2 and day 3 indexing")
	indexWG.Wait()

	// loop through day1 and write all results
	consolidateResults(drrDay2Index, drrDay3Index, args)
}
