package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/timartiny/v4vsv6"
)

type Question3SimpleResult struct {
	Domain       string
	CountryCode  string
	Censored     bool
	ControlCount int
}

type CountryCodeDomainToCounter map[string]map[string]Counter

// printCensoredDomainData will make a directory in the dataFolder called
// Question3 and make a file for each country code that lists the domains that
// are censored in each country. A domain is censored in a country if fraction
// of censored queries to total queries is higher than the user provided
// fraction
func printCensoredDomainData(
	dataFolder string,
	ccdtc CountryCodeDomainToCounter,
	ccdtcControl CountryCodeDomainToCounter,
	censorshipFraction float64,
) {
	infoLogger.Println("Writing which domains are censored in which countries," +
		" regardless of control domains",
	)
	infoLogger.Printf("Using censorship fraction: %f\n", censorshipFraction)
	parentFolderPath := filepath.Join(dataFolder, "Question3")
	err := os.MkdirAll(parentFolderPath, os.ModePerm)
	if err != nil {
		errorLogger.Fatalf("Error creating directory: %v\n", err)
	}
	fullFolderPath := filepath.Join(parentFolderPath, "full")
	err = os.MkdirAll(fullFolderPath, os.ModePerm)
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
		}()
	}

	infoLogger.Println(
		"Done writing all data, now doing only resolvers that answered control" +
			" domains successfully",
	)

	fullFolderPath = filepath.Join(parentFolderPath, "passesControl")
	err = os.MkdirAll(fullFolderPath, os.ModePerm)
	if err != nil {
		errorLogger.Fatalf("Error creating directory: %v\n", err)
	}

	for cc, dtc := range ccdtcControl {
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
		}()
	}

}

// updateCountryDomainMap will read Simple results from the channel and update
// the counter on whether an individual resolver has censored a domain in a
// country
func updateCountryDomainMap(
	srChan <-chan Question3SimpleResult,
	ccdtc CountryCodeDomainToCounter,
	ccdtcControl CountryCodeDomainToCounter,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	for sr := range srChan {
		if ccdtc[sr.CountryCode] == nil {
			dtc := make(map[string]Counter)
			ccdtc[sr.CountryCode] = dtc
		}
		if ccdtcControl[sr.CountryCode] == nil {
			dtc := make(map[string]Counter)
			ccdtcControl[sr.CountryCode] = dtc
		}
		// only update control map if this result came from a resolver that
		// resolved all the control domains successfully
		if sr.ControlCount == len(controlDomains)*2 {
			counter := ccdtcControl[sr.CountryCode][sr.Domain]
			if sr.Censored {
				counter.Censored++
			} else {
				counter.Uncensored++
			}
			ccdtcControl[sr.CountryCode][sr.Domain] = counter
		}
		// always update this
		counter := ccdtc[sr.CountryCode][sr.Domain]
		if sr.Censored {
			counter.Censored++
		} else {
			counter.Uncensored++
		}
		ccdtc[sr.CountryCode][sr.Domain] = counter
	}
}

// determineCountryCensorship will receive a result struct, parse the
// struct and determine if it indicates censorship, create a simplified struct
// for updating in memory storage, and send that along
func determineCountryCensorship(
	drrChan <-chan v4vsv6.DomainResolverResult,
	srChan chan<- Question3SimpleResult,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	for drr := range drrChan {
		if isControlDomain(drr) {
			continue
		}
		var sr Question3SimpleResult
		sr.Domain = drr.Domain
		sr.CountryCode = drr.ResolverCountry
		sr.Censored = drr.CensoredQuery
		sr.ControlCount = resolvers[drr.ResolverIP].ControlCount
		srChan <- sr
	}
}

// Question3 will answer the question: which domains are censored in which
// countries.
func Question3(args InterpretResultsFlags) {
	infoLogger.Printf(
		"Answering Question 3, which domains are censored in which countries",
	)
	domainResolverResultChannel := make(chan v4vsv6.DomainResolverResult)
	simplifiedResultChannel := make(chan Question3SimpleResult)
	var readFileWG sync.WaitGroup
	var lineToDetermineCensorshipWG sync.WaitGroup
	var updateMapWG sync.WaitGroup
	countryCodeDomainToCounter := make(CountryCodeDomainToCounter)
	controlCountryCodeDomainToCounter := make(CountryCodeDomainToCounter)

	for i := 0; i < args.Workers; i++ {
		lineToDetermineCensorshipWG.Add(1)
		go determineCountryCensorship(
			domainResolverResultChannel,
			simplifiedResultChannel,
			&lineToDetermineCensorshipWG,
		)
	}
	updateMapWG.Add(1)
	go updateCountryDomainMap(
		simplifiedResultChannel,
		countryCodeDomainToCounter,
		controlCountryCodeDomainToCounter,
		&updateMapWG,
	)
	readFileWG.Add(1)
	go readDomainResolverResults(
		args.ResultsFile,
		domainResolverResultChannel,
		&readFileWG,
	)
	infoLogger.Printf("Waiting for list of country codes\n")
	readFileWG.Wait()
	close(domainResolverResultChannel)
	infoLogger.Println("Written everything to determineCensorshipAndSendResult, waiting...")
	lineToDetermineCensorshipWG.Wait()
	infoLogger.Printf("Determined all the censorship, waiting on map updates...")
	close(simplifiedResultChannel)
	updateMapWG.Wait()

	printCensoredDomainData(
		args.DataFolder,
		countryCodeDomainToCounter,
		controlCountryCodeDomainToCounter,
		args.CensorshipFraction,
	)

}
