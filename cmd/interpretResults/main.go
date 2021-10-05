package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/alexflint/go-arg"
	"github.com/timartiny/v4vsv6"
)

var (
	infoLogger  *log.Logger
	errorLogger *log.Logger
)

type InterpretResultsFlags struct {
	DataFolder         string  `arg:"--data-folder,required" help:"(Required) Path to the folder to store intreted results" json:"data_folder"`
	ResultsFile        string  `arg:"--results-file,required" help:"(Required) Path to the file containing the DomainResolverResults" json:"results_file"`
	Workers            int     `arg:"-w,--workers" help:"Number of workers to work simultaneously" default:"5" json:"wokers"`
	CensorshipFraction float64 `arg:"-f,--fraction" help:"Fraction of queries that don't support TLS that should be considered censorship" default:"0.5" json:"censorship_fraction"`
}

type SimplifiedResult struct {
	Domain      string
	CountryCode string
	Censored    bool
}

type Counter struct {
	Censored   int
	Uncensored int
}

type CountryCodeDomainToCounter map[string]map[string]Counter

func setupArgs() InterpretResultsFlags {
	var ret InterpretResultsFlags
	arg.MustParse(&ret)

	return ret
}

// censoredDomainsQuestion will read lines from the provided file and get the
// unique country codes. It will store the unique ones, while also passing them
// through a channel to workers to read the file again but only for that country
func censoredDomainsQuestion(
	path string,
	drrChan chan<- v4vsv6.DomainResolverResult,
	ccChan chan<- []string,
) {
	resultsFile, err := os.Open(path)
	if err != nil {
		errorLogger.Fatalf("Error opening results file, %v\n", err)
	}
	defer resultsFile.Close()

	var ret []string
	tmp := make(map[string]bool)
	scanner := bufio.NewScanner(resultsFile)

	for scanner.Scan() {
		line := scanner.Text()
		var drr v4vsv6.DomainResolverResult
		json.Unmarshal([]byte(line), &drr)
		if _, ok := tmp[drr.ResolverCountry]; !ok {
			tmp[drr.ResolverCountry] = true
			ret = append(ret, drr.ResolverCountry)
		}
		drrChan <- drr
	}

	ccChan <- ret
}

// determineCensorship will read through a slice of AdressResults and say there
// is no censorship if all the IPs are filled in and SupportsTLS is true.
// Otherwise false. If there are different results between entries in slice it
// will point them out.
func determineCensorship(drr v4vsv6.DomainResolverResult) bool {
	ret := drr.Results[0].SupportsTLS

	for _, ar := range drr.Results[1:] {
		if ar.SupportsTLS != ret {
			// should print this once we have more reliable data...
			// infoLogger.Printf("drr has mixed SupportsTLS results: %+v\n", drr)
			return false
		}
	}

	return ret
}

// determineCensorshipAndSendResult will receive a result struct, parse the
// struct and determine if it indicates censorship, create a simplified struct
// for updating in memory storage, and send that along
func determineCensorshipAndSendResult(
	drrChan <-chan v4vsv6.DomainResolverResult,
	srChan chan<- SimplifiedResult,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	for drr := range drrChan {
		var sr SimplifiedResult
		sr.Domain = drr.Domain
		sr.CountryCode = drr.ResolverCountry
		sr.Censored = determineCensorship(drr)
		srChan <- sr
	}
}

// updateMap will read Simple results from the channel and update the counter on
// whether an individual resolver has censored a domain in a country
func updateMap(
	srChan <-chan SimplifiedResult,
	ccdtc CountryCodeDomainToCounter,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	for sr := range srChan {
		if ccdtc[sr.CountryCode] == nil {
			dtc := make(map[string]Counter)
			ccdtc[sr.CountryCode] = dtc
		}
		counter := ccdtc[sr.CountryCode][sr.Domain]
		if sr.Censored {
			counter.Censored++
		} else {
			counter.Uncensored++
		}
		ccdtc[sr.CountryCode][sr.Domain] = counter
	}
}

// printCensoredDomainData will make a directory in the dataFolder called
// Question3 and make a file for each country code that lists the domains that
// are censored in each country. A domain is censored in a country if fraction
// of censored queries to total queries is higher than the user provided
// fraction
func printCensoredDomainData(
	dataFolder string,
	ccdtc CountryCodeDomainToCounter,
	censorshipFraction float64,
) {
	infoLogger.Println("Writing which domains are censored in which countries")
	infoLogger.Printf("Using censorship fraction: %f\n", censorshipFraction)
	fullFolderPath := filepath.Join(dataFolder, "Question3")
	err := os.MkdirAll(fullFolderPath, os.ModePerm)
	if err != nil {
		errorLogger.Fatalf("Error creating directory: %v\n", err)
	}

	for cc, dtc := range ccdtc {
		// wrapper function for opening and deferring closure of a lot of files.
		func() {
			ccFile, err := os.Create(filepath.Join(fullFolderPath, cc+".txt"))
			if err != nil {
				errorLogger.Fatalf("Error creating country code file: %v\n", err)
			}
			defer ccFile.Close()
			ccFile.WriteString(fmt.Sprintf("Censored Domains in %s\n", cc))

			for domain, counter := range dtc {
				total := float64(counter.Censored + counter.Uncensored)
				if float64(counter.Censored)/total >= censorshipFraction {
					ccFile.WriteString(fmt.Sprintf("%s\n", domain))
				}
			}
			infoLogger.Printf("Completed writing %s, closing it\n", ccFile.Name())
		}()
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

	args := setupArgs()
	infoLogger.Printf("Num Workers: %d\n", args.Workers)

	domainResolverResultChannel := make(chan v4vsv6.DomainResolverResult)
	simplifiedResultChannel := make(chan SimplifiedResult)
	countryCodeChannel := make(chan []string)
	var lineToDetermineCensorshipWG sync.WaitGroup
	var updateMapWG sync.WaitGroup
	countryCodeDomainToCounter := make(CountryCodeDomainToCounter)

	infoLogger.Println("Getting a list of all the countries we have resolvers in")
	for i := 0; i < args.Workers; i++ {
		lineToDetermineCensorshipWG.Add(1)
		go determineCensorshipAndSendResult(
			domainResolverResultChannel,
			simplifiedResultChannel,
			&lineToDetermineCensorshipWG,
		)
	}
	updateMapWG.Add(1)
	go updateMap(simplifiedResultChannel, countryCodeDomainToCounter, &updateMapWG)
	go censoredDomainsQuestion(
		args.ResultsFile,
		domainResolverResultChannel,
		countryCodeChannel,
	)
	infoLogger.Printf("Waiting for list of country codes\n")
	countrySlice := <-countryCodeChannel
	infoLogger.Printf("Have %d countries, first 10: %v\n", len(countrySlice), countrySlice[:10])
	close(domainResolverResultChannel)
	infoLogger.Println("Written everything to determineCensorshipAndSendResult, waiting...")
	lineToDetermineCensorshipWG.Wait()
	infoLogger.Printf("Determined all the censorship, waiting on map updates...")
	close(simplifiedResultChannel)
	updateMapWG.Wait()

	printCensoredDomainData(
		args.DataFolder,
		countryCodeDomainToCounter,
		args.CensorshipFraction,
	)
}
