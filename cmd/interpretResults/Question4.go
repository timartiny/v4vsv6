package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/timartiny/v4vsv6"
)

type ResolverPair struct {
	V4 string `json:"v4"`
	V6 string `json:"v6"`
}

type Question4SimpleResult struct {
	Domain                      string
	CountryCode                 string
	CensoringPairs              []ResolverPair
	CensoringV4Resolvers        map[string]struct{}
	CensoringV6Resolvers        map[string]struct{}
	CensoredARequests           int
	ControlCensoredARequests    int
	CensoredAAAARequests        int
	ControlCensoredAAAARequests int
}

type Question4Output struct {
	Domain               string         `json:"domain"`
	TotalPairs           int            `json:"total_pairs"`
	CensoringPairs       []ResolverPair `json:"censoring_pairs"`
	TotalV4              int            `json:"total_v4"`
	CensoringV4Resolvers []string       `json:"censoring_v4_resolvers"`
	TotalV6              int            `json:"total_v6"`
	CensoringV6Resolvers []string       `json:"censoring_v6_resolvers"`
	CensoredARequests    int            `json:"censored_a_requests"`
	CensoredAAAARequests int            `json:"censored_aaaa_requests"`
}

type CountryCodeDomainToSimpleResult map[string]map[string]*Question4SimpleResult

// getQuestion4SimpleResults will take DomainResolverResults and get the
// Question 4 Simple Results extracted from it, then pass the simple result on
// to updating the local map
func getQuestion4SimpleResults(
	drrChan <-chan v4vsv6.DomainResolverResult,
	srChan chan<- *Question4SimpleResult,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	for drr := range drrChan {
		sr := new(Question4SimpleResult)
		sr.Domain = drr.Domain
		sr.CountryCode = drr.ResolverCountry
		sr.CensoringV4Resolvers = make(map[string]struct{})
		sr.CensoringV6Resolvers = make(map[string]struct{})
		if !isControlDomain(drr) {
			if isCensorship(drr) {
				tmpIP := net.ParseIP(drr.ResolverIP)
				if tmpIP == nil {
					errorLogger.Printf("Invalid IP provided: %v\n", drr.ResolverIP)
					errorLogger.Printf("Skipping this entry")
					continue
				}
				if tmpIP.To4() != nil {
					sr.CensoringV4Resolvers[tmpIP.String()] = struct{}{}
				} else {
					sr.CensoringV6Resolvers[tmpIP.String()] = struct{}{}
				}
				if drr.RequestedAddressType == "A" {
					sr.CensoredARequests++
					if resolvers[drr.ResolverIP].ControlCount == len(controlDomains)*2 {
						sr.ControlCensoredARequests++
					}
				} else {
					sr.CensoredAAAARequests++
					if resolvers[drr.ResolverIP].ControlCount == len(controlDomains)*2 {
						sr.ControlCensoredAAAARequests++
					}
				}
			}
		}

		srChan <- sr
	}
}

// updateCountryDomainQuestion4Map will read in simplified results and update
// the mapping from country code and domain to the simplified results. It will
// create sub maps as needed.
func updateCountryDomainQuestion4Map(
	srChan <-chan *Question4SimpleResult,
	ccdtsr CountryCodeDomainToSimpleResult,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	for sr := range srChan {
		// if this is the first time we've seen the country code, add a new map
		if ccdtsr[sr.CountryCode] == nil {
			dtsr := make(map[string]*Question4SimpleResult)
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
			for k := range sr.CensoringV4Resolvers {
				if _, ok := existingSR.CensoringV4Resolvers[k]; ok {
					// we already know this domain is censored, by this
					// resolver, this happens because each resolver is asked to
					// resolver each domain for a v4 and v6 address
					continue
				}
				existingSR.CensoringV4Resolvers[k] = struct{}{}
			}
			// this should only be one pass through, since srs are only made
			// with one entry
			for k := range sr.CensoringV6Resolvers {
				if _, ok := existingSR.CensoringV6Resolvers[k]; ok {
					// we already know this domain is censored, by this resolver
					// this happens because each resolver is asked to resolver
					// each domain for a v4 and v6 address.
					continue
				}
				existingSR.CensoringV6Resolvers[k] = struct{}{}
			}
			existingSR.CensoredARequests += sr.CensoredARequests
			existingSR.ControlCensoredARequests += sr.ControlCensoredARequests
			existingSR.CensoredAAAARequests += sr.CensoredAAAARequests
			existingSR.ControlCensoredAAAARequests += sr.ControlCensoredAAAARequests
		}
	}
}

// pairCensoringResolvers will go through the CountryCodeDomainToSimpleResult
// mapping and pull out pairs of CensoringV{4,6}Resolvers and put them into a
// ResolverPair and that into the CensoringPair
func pairCensoringResolvers(
	ccdtsr CountryCodeDomainToSimpleResult,
	v4ToV6 map[string]string,
) {
	for _, dtsr := range ccdtsr {
		for _, sr := range dtsr {
			for v4Resolver := range sr.CensoringV4Resolvers {
				v6Pair := v4ToV6[v4Resolver]
				// infoLogger.Printf("v4Resolver: %v, v6Pair: %v\n", v4Resolver, v6Pair)
				if _, ok := sr.CensoringV6Resolvers[v6Pair]; ok {
					// infoLogger.Printf("The following pair censors: %v, %v\n", v4Resolver, v6Pair)
					// the pair censors!
					rp := ResolverPair{V4: v4Resolver, V6: v6Pair}
					sr.CensoringPairs = append(sr.CensoringPairs, rp)
					delete(sr.CensoringV4Resolvers, v4Resolver)
					delete(sr.CensoringV6Resolvers, v6Pair)
				}
			}
			// don't need to check CensoringV6Resolvers, if we didn't flag it in
			// v4 then the v6's pair won't be there
		}
	}

}

// printQuestion4Results will make a directory in the dataFolder called Question
// 4 and make a file for each country code. In the country code files each line
// will be a JSON object of Question4Ouput.
func printQuestion4Results(
	dataFolder string,
	ccdtsr CountryCodeDomainToSimpleResult,
) {
	parentFolderPath := filepath.Join(dataFolder, "Question4")
	err := os.MkdirAll(parentFolderPath, os.ModePerm)
	if err != nil {
		errorLogger.Fatalf("Error creating directory: %v\n", err)
	}

	for _, dataType := range []string{"full", "passesControl"} {
		fullFolderPath := filepath.Join(parentFolderPath, dataType)
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
					var q4o Question4Output
					q4o.Domain = domain
					if dataType == "passesControl" {
						for _, pair := range simpleResult.CensoringPairs {
							if resolvers[pair.V4].ControlCount == len(controlDomains)*2 {
								if resolvers[pair.V6].ControlCount == len(controlDomains)*2 {
									q4o.CensoringPairs = append(q4o.CensoringPairs, pair)
								} else {
									q4o.CensoringV4Resolvers = append(q4o.CensoringV4Resolvers, pair.V4)
								}
							} else {
								if resolvers[pair.V6].ControlCount == len(controlDomains)*2 {
									q4o.CensoringV6Resolvers = append(q4o.CensoringV6Resolvers, pair.V6)
								}
							}
						}

						q4o.TotalPairs = len(q4o.CensoringPairs)
					} else {
						q4o.TotalPairs = len(simpleResult.CensoringPairs)
						q4o.CensoringPairs = simpleResult.CensoringPairs
					}

					q4o.CensoringV4Resolvers = make([]string, q4o.TotalV4)
					i := 0
					for key := range simpleResult.CensoringV4Resolvers {
						if dataType == "full" || resolvers[key].ControlCount == len(controlDomains)*2 {
							q4o.CensoringV4Resolvers[i] = key
							i++
						}
					}
					q4o.TotalV4 = len(q4o.CensoringV4Resolvers)

					q4o.CensoringV6Resolvers = make([]string, q4o.TotalV6)
					i = 0
					for key := range simpleResult.CensoringV6Resolvers {
						if dataType == "full" || resolvers[key].ControlCount == len(controlDomains)*2 {
							q4o.CensoringV6Resolvers[i] = key
							i++
						}
					}
					q4o.TotalV6 = len(q4o.CensoringV6Resolvers)

					if dataType == "passesControl" {
						q4o.CensoredARequests = simpleResult.ControlCensoredARequests
						q4o.CensoredAAAARequests = simpleResult.ControlCensoredAAAARequests
					} else {
						q4o.CensoredARequests = simpleResult.CensoredARequests
						q4o.CensoredAAAARequests = simpleResult.CensoredAAAARequests
					}

					bs, err := json.Marshal(&q4o)
					if err != nil {
						errorLogger.Printf("Error Marshaling pair struct: %+v\n", q4o)
					}
					ccFile.Write(bs)
					ccFile.WriteString("\n")
				}
			}()
		}
	}
}

func Question4(
	args InterpretResultsFlags,
	v4ToV6, v6ToV4 map[string]string,
) {
	infoLogger.Println(
		"Answering Question 4: How were domains censored by resolver address " +
			"family and by record requests",
	)
	domainResolverResultChannel := make(chan v4vsv6.DomainResolverResult)
	simplifiedResultChannel := make(chan *Question4SimpleResult)
	var getSimpleResultsWG sync.WaitGroup
	var updateMapWG sync.WaitGroup
	var doubleResolverMapWG sync.WaitGroup
	var readFileWG sync.WaitGroup
	countryCodeDomainToSimpleResult := make(CountryCodeDomainToSimpleResult)

	for i := 0; i < args.Workers; i++ {
		getSimpleResultsWG.Add(1)
		go getQuestion4SimpleResults(
			domainResolverResultChannel,
			simplifiedResultChannel,
			&getSimpleResultsWG,
		)
	}

	updateMapWG.Add(1)
	go updateCountryDomainQuestion4Map(
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

	// only check v4ToV6 because we only need that one
	if len(v4ToV6) == 0 {
		// This only happens if Question 1 isn't answered on this run
		doubleResolverMapWG.Add(1)
		go getResolverPairs(v4ToV6, v6ToV4, args.ResolverFile, &doubleResolverMapWG)
	}

	infoLogger.Println("Reading data for Question 4")
	readFileWG.Wait()
	close(domainResolverResultChannel)

	infoLogger.Println(
		"Read all the data in, waiting for Question 4 Simple Results to be " +
			"sent",
	)
	getSimpleResultsWG.Wait()
	close(simplifiedResultChannel)

	infoLogger.Println(
		"Parsed all data into Simple Results waiting for map to update",
	)
	updateMapWG.Wait()

	infoLogger.Println(
		"Question 4 data collected and organized, waiting for resolver pairs " +
			"to be organized",
	)

	doubleResolverMapWG.Wait()
	infoLogger.Println("Resolvers paired together, simplifying data by pairs")
	pairCensoringResolvers(countryCodeDomainToSimpleResult, v4ToV6)
	printQuestion4Results(args.DataFolder, countryCodeDomainToSimpleResult)
}
