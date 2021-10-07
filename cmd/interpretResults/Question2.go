package main

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
)

type Question2Output struct {
	V4IP              string `json:"v4_ip"`
	V6IP              string `json:"v6_ip"`
	ACensoredCount    int    `json:"a_censored_count"`
	AAAACensoredCount int    `json:"aaaa_censored_count"`
}

type Question2Summary struct {
	CountryCode      string  `json:"country_code"`
	ACensoredData    []int   `json:"a_censored_data"`
	AAAACensoredData []int   `json:"aaaa_censored_data"`
	ATotal           int     `json:"a_total"`
	AAAATotal        int     `json:"aaaa_total"`
	AAverage         float64 `json:"a_avg"`
	AAAAAverage      float64 `json:"aaaa_avg"`
	AMedian          float64 `json:"a_median"`
	AAAAMedian       float64 `json:"aaaa_median"`
	AStdDev          float64 `json:"a_std_dev"`
	AAAAStdDev       float64 `json:"aaaa_std_dev"`
}

// question2Stats will take a summary for a country and fill out the missing
// stats: average, median, std dev
func question2Stats(q2s *Question2Summary) {
	q2s.AAverage = float64(q2s.ATotal) / float64(len(q2s.ACensoredData))
	q2s.AMedian = findMedian(q2s.ACensoredData)
	stdSum := 0.0
	for _, v := range q2s.ACensoredData {
		stdSum += math.Pow(float64(v)-q2s.AAverage, 2.0)
	}
	q2s.AStdDev = math.Sqrt(stdSum / float64(len(q2s.ACensoredData)))

	q2s.AAAAAverage = float64(q2s.AAAATotal) / float64(len(q2s.AAAACensoredData))
	q2s.AAAAMedian = findMedian(q2s.AAAACensoredData)
	stdSum = 0.0
	for _, v := range q2s.AAAACensoredData {
		stdSum += math.Pow(float64(v)-q2s.AAAAAverage, 2.0)
	}
	q2s.AAAAStdDev = math.Sqrt(stdSum / float64(len(q2s.AAAACensoredData)))
}

// printCensoringRecordData will make a directory in the dataFolder called
// Question 2 and make a file for each country code. In the country code files
// each line will be a JSON object of Question2Ouput. Finally this will create a
// summary file where each line is a JSON object of Question2Summary
func printCensoringRecordData(
	dataFolder string,
	ccrtsr CountryCodeResolverToSimpleResult,
	v4ToV6, v6ToV4 map[string]string,
) {
	fullFolderPath := filepath.Join(dataFolder, "Question2")
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
		var q2s Question2Summary
		q2s.CountryCode = cc
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
				seenResolvers[resolver] = struct{}{}
				pair := findPair(resolver, v4ToV6, v6ToV4)
				seenResolvers[pair] = struct{}{}
				v4, v6 := organizePair(simpleResult, rtsr[pair])

				// now everything is marked as seen, actually print data.
				var q2o Question2Output
				q2o.V4IP = v4.IP
				q2o.ACensoredCount = len(v4.ACensoredDomains) + len(v6.ACensoredDomains)
				q2s.ACensoredData = append(q2s.ACensoredData, q2o.ACensoredCount)
				q2s.ATotal += q2o.ACensoredCount

				q2o.V6IP = v6.IP
				q2o.AAAACensoredCount = len(v6.AAAACensoredDomains) + len(v4.AAAACensoredDomains)
				q2s.AAAACensoredData = append(q2s.AAAACensoredData, q2o.AAAACensoredCount)
				q2s.AAAATotal += q2o.AAAACensoredCount

				bs, err := json.Marshal(&q2o)
				if err != nil {
					errorLogger.Printf("Error Marshaling pair struct: %+v\n", q2o)
				}
				ccFile.Write(bs)
				ccFile.WriteString("\n")
			}
		}()
		question2Stats(&q2s)
		bs, err := json.Marshal(&q2s)
		if err != nil {
			errorLogger.Printf("Error marshaling summary struct: %+v\n", q2s)
		}
		summaryFile.Write(bs)
		summaryFile.WriteString("\n")
	}
}

// Question2 will answer whether countries censor differently based on A/AAAA
// record requests. It can use the same data as Question 1 if Question 1 is
// already answered, if not just do question 1
func Question2(
	args InterpretResultsFlags,
	countryCodeResolverToSimpleResult CountryCodeResolverToSimpleResult,
	v4ToV6, v6ToV4 map[string]string,
) {

	if len(countryCodeResolverToSimpleResult) == 0 || len(v4ToV6) == 0 || len(v6ToV4) == 0 {
		// Question 1 not been answered, so we need to get the data, call
		// Question1 but don't print
		infoLogger.Println("Need to get data from Question 1")
		Question1(args, countryCodeResolverToSimpleResult, v4ToV6, v6ToV4, false)
	}

	printCensoringRecordData(
		args.DataFolder,
		countryCodeResolverToSimpleResult,
		v4ToV6,
		v6ToV4,
	)

}
