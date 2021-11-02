package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/timartiny/v4vsv6"
)

type Question5SimpleResult struct {
	Domain        string
	CountryCode   string
	IPs           map[string]struct{}
	V4IPs         map[string]struct{}
	V6IPs         map[string]struct{}
	CensoredV4IPs map[string]struct{}
	CensoredV6IPs map[string]struct{}
}

type Question5Output struct {
	Domain            string `json:"domain"`
	UniqueIPCount     int    `json:"unique_ip_count"`
	UniqueV4IPCount   int    `json:"unique_v4_ip_count"`
	UniqueV6IPCount   int    `json:"unique_v6_ip_count"`
	CensoredV4IPCount int    `json:"censored_v4_ip_count"`
	CensoredV6IPCount int    `json:"censored_v6_ip_count"`
}

type CountryCodeDomainToQuestion5SimpleResult map[string]map[string]*Question5SimpleResult

// getQuestion5SimpleResults will take DomainResolverResults and get the
// Question 5 Simple Results extracted from it, then pass the simple result on
// to updating the local map
func getQuestion5SimpleResults(
	drrChan <-chan v4vsv6.DomainResolverResult,
	srChan chan<- *Question5SimpleResult,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	for drr := range drrChan {
		sr := new(Question5SimpleResult)
		sr.IPs = make(map[string]struct{})
		sr.V4IPs = make(map[string]struct{})
		sr.V6IPs = make(map[string]struct{})
		sr.CensoredV4IPs = make(map[string]struct{})
		sr.CensoredV6IPs = make(map[string]struct{})
		sr.Domain = drr.Domain
		sr.CountryCode = drr.ResolverCountry
		for _, result := range drr.Results {
			if _, ok := sr.IPs[result.IP]; ok {
				// already seen this IP for this domain, from this result, skip it
				continue
			}
			if len(result.IP) <= 0 {
				// got an error with this result, don't do any IP stuff
				continue
			}
			tmpIP := net.ParseIP(result.IP)
			if tmpIP == nil {
				errorLogger.Printf("Invalid IP provided: %v\n", result.IP)
				errorLogger.Printf("Result: %+v\n", result)
				errorLogger.Printf("Skipping this entry")
				continue
			}
			sr.IPs[result.IP] = struct{}{}
			if tmpIP.To4() != nil {
				sr.V4IPs[result.IP] = struct{}{}
				if !result.SupportsTLS {
					sr.CensoredV4IPs[result.IP] = struct{}{}
				}
			} else {
				sr.V6IPs[result.IP] = struct{}{}
				if !result.SupportsTLS {
					sr.CensoredV6IPs[result.IP] = struct{}{}
				}
			}

		}
		if len(sr.IPs) > 0 {
			srChan <- sr
		}
	}
}

// updateCountryDomainQuestion5Map will read in simplified results and update
// the mapping from country code and domain to the simplified results. It will
// create sub maps as needed.
func updateCountryDomainQuestion5Map(
	srChan <-chan *Question5SimpleResult,
	ccdtsr CountryCodeDomainToQuestion5SimpleResult,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	for sr := range srChan {
		// if this is the first time we've seen the country code, add a new map
		if ccdtsr[sr.CountryCode] == nil {
			dtsr := make(map[string]*Question5SimpleResult)
			ccdtsr[sr.CountryCode] = dtsr
		}
		existingSR := ccdtsr[sr.CountryCode][sr.Domain]
		// if this is the first time we've seen this domain, then our received
		// sr is the whole data so far
		if existingSR == nil {
			ccdtsr[sr.CountryCode][sr.Domain] = sr
		} else {
			// this should only be one pass through, since srs are only made
			// with one entry
			for k := range sr.IPs {
				// this is a map, so not a big deal if we are recreating an
				// entry
				existingSR.IPs[k] = struct{}{}
				if _, ok := sr.V4IPs[k]; ok {
					existingSR.V4IPs[k] = struct{}{}
					if _, ok2 := sr.CensoredV4IPs[k]; ok2 {
						existingSR.CensoredV4IPs[k] = struct{}{}
					}
				} else {
					existingSR.V6IPs[k] = struct{}{}
					if _, ok2 := sr.CensoredV6IPs[k]; ok2 {
						existingSR.CensoredV6IPs[k] = struct{}{}
					}
				}
			}
		}
	}
}

// printQuestion5Results will make a directory in the dataFolder called Question
// 5 and make a file for each country code. In the country code files each line
// will be a JSON object of Question5Ouput.
func printQuestion5Results(
	dataFolder string,
	ccdtsr CountryCodeDomainToQuestion5SimpleResult,
) {
	fullFolderPath := filepath.Join(dataFolder, "Question5")
	err := os.MkdirAll(fullFolderPath, os.ModePerm)
	if err != nil {
		errorLogger.Fatalf("Error creating directory: %v\n", err)
	}

	for cc, dtsr := range ccdtsr {
		func() {
			ccFile, err := os.Create(filepath.Join(fullFolderPath, cc+".json"))
			if err != nil {
				errorLogger.Fatalf("Error creating country code file: %v\n", err)
			}
			defer ccFile.Close()

			for domain, simpleResult := range dtsr {
				var q5o Question5Output
				q5o.Domain = domain
				q5o.UniqueIPCount = len(simpleResult.IPs)
				q5o.UniqueV4IPCount = len(simpleResult.V4IPs)
				q5o.UniqueV6IPCount = len(simpleResult.V6IPs)
				q5o.CensoredV4IPCount = len(simpleResult.CensoredV4IPs)
				q5o.CensoredV6IPCount = len(simpleResult.CensoredV6IPs)

				bs, err := json.Marshal(&q5o)
				if err != nil {
					errorLogger.Printf("Error Marshaling pair struct: %+v\n", q5o)
				}
				ccFile.Write(bs)
				ccFile.WriteString("\n")
			}
		}()
	}
}

func Question5(
	args InterpretResultsFlags,
) {
	infoLogger.Println(
		"Answering Question 5: How many IPs were returned for each Domain, " +
			"and how do they breakdown along censored/uncensored",
	)
	domainResolverResultChannel := make(chan v4vsv6.DomainResolverResult)
	simplifiedResultChannel := make(chan *Question5SimpleResult)
	var getSimpleResultsWG sync.WaitGroup
	var updateMapWG sync.WaitGroup
	var readFileWG sync.WaitGroup
	countryCodeDomainToSimpleResult := make(CountryCodeDomainToQuestion5SimpleResult)

	for i := 0; i < args.Workers; i++ {
		getSimpleResultsWG.Add(1)
		go getQuestion5SimpleResults(
			domainResolverResultChannel,
			simplifiedResultChannel,
			&getSimpleResultsWG,
		)
	}

	updateMapWG.Add(1)
	go updateCountryDomainQuestion5Map(
		simplifiedResultChannel,
		countryCodeDomainToSimpleResult,
		&updateMapWG,
	)

	readFileWG.Add(1)
	go readDomainResolverResults(
		args.ResultsFile,
		domainResolverResultChannel,
		&readFileWG,
	)

	infoLogger.Println("Reading data for Question 5")
	readFileWG.Wait()
	close(domainResolverResultChannel)

	infoLogger.Println(
		"Read all the data in, waiting for Question 5 Simple Results to be " +
			"sent",
	)
	getSimpleResultsWG.Wait()
	close(simplifiedResultChannel)

	infoLogger.Println(
		"Parsed all data into Simple Results waiting for map to update",
	)
	updateMapWG.Wait()

	infoLogger.Println(
		"Question 5 data collected and organized, printing results",
	)

	printQuestion5Results(args.DataFolder, countryCodeDomainToSimpleResult)
}
