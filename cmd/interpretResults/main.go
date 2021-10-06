package main

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
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
	ResolverFile       string  `arg:"-r,--resolver-file,quired" help:"(Required) Path to the file containing the Resolver Pairings, needed to format output of Question 1" json:"resolver_file"`
}

type Counter struct {
	Censored   int
	Uncensored int
}

func setupArgs() InterpretResultsFlags {
	var ret InterpretResultsFlags
	arg.MustParse(&ret)

	return ret
}

// readDomainResolverResults will read lines from the provided file. It will
// pass them through a channel to workers to process the structs
func readDomainResolverResults(
	path string,
	drrChan chan<- v4vsv6.DomainResolverResult,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	resultsFile, err := os.Open(path)
	if err != nil {
		errorLogger.Fatalf("Error opening results file, %v\n", err)
	}
	defer resultsFile.Close()

	scanner := bufio.NewScanner(resultsFile)

	for scanner.Scan() {
		line := scanner.Text()
		var drr v4vsv6.DomainResolverResult
		json.Unmarshal([]byte(line), &drr)
		drrChan <- drr
	}
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
	infoLogger.Printf(
		"Each question will be answered one at a time, using %d workers\n",
		args.Workers,
	)

	Question1(args)
	// Question3(args)
}
