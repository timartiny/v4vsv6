package main

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"sort"
	"sync"

	"github.com/alexflint/go-arg"
	"github.com/timartiny/v4vsv6"
)

var (
	infoLogger     *log.Logger
	errorLogger    *log.Logger
	controlDomains map[string]struct{}
)

type InterpretResultsFlags struct {
	DateString         string  `arg:"--date-string,required" help:"(Required) String that is appended/prepended to files with the date"`
	DataFolder         string  `arg:"--data-folder,required" help:"(Required) Path to the folder to store answer to questions" json:"data_folder"`
	ResultsFile        string  `arg:"--results-file,required" help:"(Required) Path to the file containing the DomainResolverResults" json:"results_file"`
	Workers            int     `arg:"-w,--workers" help:"Number of workers to work simultaneously" default:"5" json:"wokers"`
	CensorshipFraction float64 `arg:"-f,--fraction" help:"Fraction of queries that don't support TLS that should be considered censorship" default:"0.5" json:"censorship_fraction"`
	ResolverFile       string  `arg:"-r,--resolver-file,required" help:"(Required) Path to the file containing the Resolver Pairings, needed to format output of Question 1" json:"resolver_file"`
	Questions          []int   `arg:"-q,--questions,separate" help:"Which questions to answer, can be supplied multiple times" json:"questions"`
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

// isCensorship is a now unneeded function, it just reads a value in the
// DomainResolverResult
func isCensorship(drr v4vsv6.DomainResolverResult) bool {
	return drr.CensoredQuery
}

// isControlDomain will check if a provided drr is for a control domain.
func isControlDomain(drr v4vsv6.DomainResolverResult) bool {
	if _, ok := controlDomains[drr.Domain]; ok {
		return true
	}

	return false
}

// resolverStats will go throug the results file and for each resolver will
// collect the number of control domains it got correct.
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
	controlDomains = map[string]struct{}{"v4vsv6.com": {}, "test1.v4vsv6.com": {}, "test2.v4vsv6.com": {}}

	v4ToV6 := make(map[string]string)
	v6ToV4 := make(map[string]string)
	// getResolverPairs(v4ToV6, v6ToV4, args.ResolverFile)
	// No question specified so answer all of them
	if len(args.Questions) == 0 {
		args.Questions = []int{1, 2, 3, 4, 5, 6}
	}

	// Answer questions in order
	sort.Ints(args.Questions)

	// Question 1 and 2 answer roughly the same question, so collection data for
	// Question 1 can just be used for Question 2
	// Question 6 gets resolver data which is used in earlier questions, so it must go first
	Question6(args, v4ToV6, v6ToV4)
	countryCodeResolverToSimpleResult := make(CountryCodeResolverToSimpleResult)
	for _, q := range args.Questions {
		switch q {
		case 1:
			Question1(
				args,
				countryCodeResolverToSimpleResult,
				v4ToV6,
				v6ToV4,
				true,
			)
		case 2:
			Question2(args, countryCodeResolverToSimpleResult, v4ToV6, v6ToV4)
		case 3:
			Question3(args)
		case 4:
			Question4(args, v4ToV6, v6ToV4)
		case 5:
			Question5(args)
		case 6:
			continue
		default:
			infoLogger.Printf("Question %d not yet implemented\n", q)
			infoLogger.Println("Question input must be 1-6")
		}
	}
}
