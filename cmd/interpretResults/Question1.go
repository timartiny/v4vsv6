package main

import (
	"encoding/json"
	"math"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/timartiny/v4vsv6"
)

// Question1SimpleResult will store, for each resolver how many domains it
// censored requests, and what those domains are
type Question1SimpleResult struct {
	IP                  string
	AF                  string
	CountryCode         string
	ACensoredDomains    map[string]struct{}
	AAAACensoredDomains map[string]struct{}
}

type Question1Output struct {
	V4IP                       string `json:"v4_ip"`
	V6IP                       string `json:"v6_ip"`
	V4CensoredCount            int    `json:"v4_censored_count"`
	V6CensoredCount            int    `json:"v6_censored_count"`
	V4CorrectControlResolution int    `json:"v4_correct_control_resolution"`
	V6CorrectControlResolution int    `json:"v6_correct_control_resolution"`
}

type Question1Summary struct {
	CountryCode                    string  `json:"country_code"`
	V4CensoredData                 []int   `json:"v4_censored_data"`
	V6CensoredData                 []int   `json:"v6_censored_data"`
	V4Total                        int     `json:"v4_total"`
	V6Total                        int     `json:"v6_total"`
	V4Average                      float64 `json:"v4_avg"`
	V6Average                      float64 `json:"v6_avg"`
	V4Median                       float64 `json:"v4_median"`
	V6Median                       float64 `json:"v6_median"`
	V4StdDev                       float64 `json:"v4_std_dev"`
	V6StdDev                       float64 `json:"v6_std_dev"`
	NumResolversPairs              int     `json:"num_resolver_pairs"`
	NumCorrectControlResolverPairs int     `json:"num_correct_control_resolver_pairs"`
}

type CountryCodeResolverToSimpleResult map[string]map[string]*Question1SimpleResult

// getQuestion1SimpleResults will take DomainResolverResults and get the
// Question 1 Simple Results extracted from it, then pass the simple result on
// to updating the local map
func getQuestion1SimpleResults(
	drrChan <-chan v4vsv6.DomainResolverResult,
	srChan chan<- *Question1SimpleResult,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	for drr := range drrChan {
		sr := new(Question1SimpleResult)
		sr.IP = drr.ResolverIP
		sr.CountryCode = drr.ResolverCountry
		tmpIP := net.ParseIP(sr.IP)
		if tmpIP == nil {
			errorLogger.Printf("Not a valid IP: %v\n", sr.IP)
			errorLogger.Printf("drr: %+v\n", drr)
			errorLogger.Println("Skipping this entry")
			continue
		}
		if tmpIP.To4() != nil {
			sr.AF = "4"
		} else {
			sr.AF = "6"
		}
		sr.ACensoredDomains = make(map[string]struct{})
		sr.AAAACensoredDomains = make(map[string]struct{})
		// don't need to check censorship of control domains, so check that
		// first
		if !isControlDomain(drr) {
			if isCensorship(drr) {
				if drr.RequestedAddressType == "A" {
					sr.ACensoredDomains[drr.Domain] = struct{}{}
				} else if drr.RequestedAddressType == "AAAA" {
					sr.AAAACensoredDomains[drr.Domain] = struct{}{}
				} else {
					errorLogger.Printf(
						"Somehow Got a requested address type that is not A or "+
							"AAAA: %s\n",
						drr.RequestedAddressType,
					)
					errorLogger.Printf("drr: %+v\n", drr)
				}
			}
		}

		srChan <- sr
	}
}

// updateCountryResolverMap will read in simplified results and update the
// mapping from country code and resolver to the simplified results. It will
// create sub maps as needed, and append uniquely censored domains as they come.
func updateCountryResolverMap(
	srChan <-chan *Question1SimpleResult,
	ccrtsr CountryCodeResolverToSimpleResult,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	for sr := range srChan {
		// if this is the first time we've seen the country code, add a new map
		if ccrtsr[sr.CountryCode] == nil {
			rtsr := make(map[string]*Question1SimpleResult)
			ccrtsr[sr.CountryCode] = rtsr
		}
		existingSR := ccrtsr[sr.CountryCode][sr.IP]
		// if this is the first time we've seen this IP, then our received sr
		// is the whole data so far
		if existingSR == nil {
			ccrtsr[sr.CountryCode][sr.IP] = sr
		} else {
			// this should only be one pass through, since srs are only made
			// with one entry
			for k := range sr.ACensoredDomains {
				if _, ok := existingSR.ACensoredDomains[k]; ok {
					// we already know this domain is censored, by this
					// resolver, for A record requests, currently this happens
					// because some v4 addresses are paired with multiple v6
					// addresses
					// infoLogger.Println(
					//  "Already saw this domain is censored by this resolver" +
					//      " on A record requests, somehow",
					// )
					continue
				}
				existingSR.ACensoredDomains[k] = struct{}{}
			}
			// this should only be one pass through, since srs are only made
			// with one entry
			for k := range sr.AAAACensoredDomains {
				if _, ok := existingSR.AAAACensoredDomains[k]; ok {
					// we already know this domain is censored, by this
					// resolver, for A record requests, currently this happens
					// because some v4 addresses are paired with multiple v6
					// addresses
					// infoLogger.Println(
					// 	"Already saw this domain is censored by this resolver" +
					// 		" on AAAA record requests, somehow",
					// )
					// infoLogger.Printf("sr: %+v\n", sr)
					continue
				}
				existingSR.AAAACensoredDomains[k] = struct{}{}
			}
		}
	}
}

// findPair will look for r in m1 and m2 (it is assumed to be in 1 only) and
// return its pair
func findPair(r string, m1, m2 map[string]string) string {
	if p, ok := m1[r]; ok {
		return p
	} else {
		if _, ok := m2[r]; !ok {
			errorLogger.Printf("Somehow %s is not in either mapping\n", r)
		}
		return m2[r]
	}
}

// organizePair will take a pair of results and return it ordered, the first the
// v4 resolver result, then the second the v6 resolver result
func organizePair(s1, s2 *Question1SimpleResult) (*Question1SimpleResult, *Question1SimpleResult) {
	var v4, v6 *Question1SimpleResult

	if s1.AF == "4" && s2.AF == "6" {
		v4 = s1
		v6 = s2
	} else if s1.AF == "6" && s2.AF == "4" {
		v4 = s2
		v6 = s1
	} else {
		errorLogger.Println("Got a pair of resolvers with the same address type")
		errorLogger.Printf("s1: %+v, s2: %+v\n", s1, s2)
	}

	return v4, v6
}

// findMedian finds the median of a slice of ints, doesn't actually sort list
func findMedian(is []int) float64 {
	if len(is) == 0 {
		return 0.0
	}
	isCopy := make([]int, len(is))
	numCopied := copy(isCopy, is)
	if numCopied != len(is) {
		errorLogger.Println("Didn't copy full list of ints")
		errorLogger.Printf(
			"Full list has %d elements, only copied %d\n",
			len(is),
			numCopied,
		)
	}
	sort.Ints(isCopy)
	middleInd := len(isCopy) / 2
	if len(isCopy)%2 == 1 {
		return float64(isCopy[middleInd])
	} else {
		return float64(
			isCopy[middleInd-1]+isCopy[middleInd],
		) / 2
	}
}

// question1Stats will take a summary for a country and fill out the missing
// stats: average, median, std dev
func question1Stats(q1s *Question1Summary) {
	q1s.V4Average = float64(q1s.V4Total) / float64(len(q1s.V4CensoredData))
	q1s.V4Median = findMedian(q1s.V4CensoredData)
	stdSum := 0.0
	for _, v := range q1s.V4CensoredData {
		stdSum += math.Pow(float64(v)-q1s.V4Average, 2.0)
	}
	q1s.V4StdDev = math.Sqrt(stdSum / float64(len(q1s.V4CensoredData)))

	q1s.V6Average = float64(q1s.V6Total) / float64(len(q1s.V6CensoredData))
	q1s.V6Median = findMedian(q1s.V6CensoredData)
	stdSum = 0.0
	for _, v := range q1s.V6CensoredData {
		stdSum += math.Pow(float64(v)-q1s.V6Average, 2.0)
	}
	q1s.V6StdDev = math.Sqrt(stdSum / float64(len(q1s.V6CensoredData)))
	if math.IsNaN(q1s.V4Average) {
		q1s.V4Average = 0.0
	}
	if math.IsNaN(q1s.V4StdDev) {
		q1s.V4StdDev = 0.0
	}
	if math.IsNaN(q1s.V6Average) {
		q1s.V6Average = 0.0
	}
	if math.IsNaN(q1s.V6StdDev) {
		q1s.V6StdDev = 0.0
	}
}

// printCensoringResolverData will make a directory in the dataFolder called
// Question 1 in there it will make two folders, full and passesControl and make
// a file for each country code. In the country code files each line will be a
// JSON object of Question1Ouput. Finally this will create a summary file where
// each line is a JSON object of Question1Summary
func printCensoringResolverData(
	dataFolder string,
	ccrtsr CountryCodeResolverToSimpleResult,
	v4ToV6, v6ToV4 map[string]string,
) {
	parentFolderPath := filepath.Join(dataFolder, "Question1")
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
		summaryFile, err := os.Create(filepath.Join(fullFolderPath, "summary.json"))
		if err != nil {
			errorLogger.Fatalf("Error creating summary file: %v\n", err)
		}
		defer summaryFile.Close()

		for cc, rtsr := range ccrtsr {
			var q1s Question1Summary
			q1s.CountryCode = cc
			func() {
				ccFile, err := os.Create(filepath.Join(fullFolderPath, cc+".json"))
				if err != nil {
					errorLogger.Fatalf("Error creating country code file: %v\n", err)
				}
				defer ccFile.Close()

				seenResolvers := make(map[string]struct{})
				for resolver, simpleResult := range rtsr {
					if _, ok := seenResolvers[resolver]; ok {
						// saw this resolver through its pair, so we're done here
						continue
					}
					if dataType == "passesControl" {
						if resolvers[simpleResult.IP].ControlCount != len(controlDomains)*2 {
							continue
						}
					}
					seenResolvers[resolver] = struct{}{}
					pair := findPair(resolver, v4ToV6, v6ToV4)
					seenResolvers[pair] = struct{}{}
					v4, v6 := organizePair(simpleResult, rtsr[pair])

					// now everything is marked as seen, actually print data.
					// we have a pair, so tally it.
					q1s.NumResolversPairs += 1
					if resolvers[v4.IP].ControlCount == len(controlDomains)*2 && resolvers[v6.IP].ControlCount == len(controlDomains)*2 {
						q1s.NumCorrectControlResolverPairs += 1
					}
					var q1o Question1Output
					q1o.V4IP = v4.IP
					q1o.V4CensoredCount = len(v4.ACensoredDomains) + len(v4.AAAACensoredDomains)
					q1o.V4CorrectControlResolution = resolvers[v4.IP].ControlCount
					q1s.V4CensoredData = append(q1s.V4CensoredData, q1o.V4CensoredCount)
					q1s.V4Total += q1o.V4CensoredCount

					q1o.V6IP = v6.IP
					q1o.V6CensoredCount = len(v6.ACensoredDomains) + len(v6.AAAACensoredDomains)
					q1o.V6CorrectControlResolution = resolvers[v6.IP].ControlCount
					q1s.V6CensoredData = append(q1s.V6CensoredData, q1o.V6CensoredCount)
					q1s.V6Total += q1o.V6CensoredCount

					bs, err := json.Marshal(&q1o)
					if err != nil {
						errorLogger.Printf("Error Marshaling pair struct: %+v\n", q1o)
					}
					ccFile.Write(bs)
					ccFile.WriteString("\n")
				}
			}()
			question1Stats(&q1s)
			bs, err := json.Marshal(&q1s)
			if err != nil {
				errorLogger.Printf("Error marshaling summary struct: %+v\n", q1s)
			}
			summaryFile.Write(bs)
			summaryFile.WriteString("\n")
		}
	}
}

// Question 1 will answer the question: Is there a difference between v4 and v6
// resolvers in countries
func Question1(
	args InterpretResultsFlags,
	countryCodeResolverToSimpleResult CountryCodeResolverToSimpleResult,
	v4ToV6, v6ToV4 map[string]string,
	printResults bool,
) {
	infoLogger.Println(
		"Answering Question 1, is there a difference between v4/v6 resolvers",
	)
	domainResolverResultChannel := make(chan v4vsv6.DomainResolverResult)
	simplifiedResultChannel := make(chan *Question1SimpleResult)
	var readFileWG sync.WaitGroup
	var getSimpleResultsWG sync.WaitGroup
	var updateMapWG sync.WaitGroup
	var doubleResolverMapWG sync.WaitGroup

	for i := 0; i < args.Workers; i++ {
		getSimpleResultsWG.Add(1)
		go getQuestion1SimpleResults(
			domainResolverResultChannel,
			simplifiedResultChannel,
			&getSimpleResultsWG,
		)
	}

	updateMapWG.Add(1)
	go updateCountryResolverMap(
		simplifiedResultChannel,
		countryCodeResolverToSimpleResult,
		&updateMapWG,
	)

	readFileWG.Add(1)
	go readDomainResolverResults(
		args.ResultsFile,
		domainResolverResultChannel,
		&readFileWG,
	)

	infoLogger.Println("Reading data file for Question 1")
	readFileWG.Wait()

	close(domainResolverResultChannel)
	infoLogger.Println(
		"Read all the data, waiting for Question 1 Simple Results to be sent " +
			"to update map",
	)

	getSimpleResultsWG.Wait()
	close(simplifiedResultChannel)

	infoLogger.Println("Parsed the Question 1 data into simple results, now " +
		"collating them into a map",
	)

	updateMapWG.Wait()

	infoLogger.Println("Question 1 data collated. Waiting of Resolver Pairs")
	doubleResolverMapWG.Wait()
	if printResults {
		infoLogger.Println("Resolver Pairs formed, printing data")

		printCensoringResolverData(args.DataFolder, countryCodeResolverToSimpleResult, v4ToV6, v6ToV4)
	}

}
