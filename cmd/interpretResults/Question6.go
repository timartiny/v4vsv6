package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/timartiny/v4vsv6"
)

var (
	resolvers map[string]ResolverStats
)

type Question6Output struct {
	Domain          string `json:"domain"`
	CountryCode     string `json:"country_code"`
	V4CensoredCount int    `json:"v4_censored_count"`
	V6CensoredCount int    `json:"v6_censored_count"`
}

type CountryCodeDomainToQuestion6Output map[string]map[string]*Question6Output

type ResolverStats struct {
	ID              string              `json:"id"`
	ResolverIP      string              `json:"resolver_ip"`
	ResolverCountry string              `json:"resolver_country"`
	ControlCount    int                 `json:"control_count"`
	BlockedDomains  map[string]struct{} `json:"blocked_domains"`
}

// getResolverPairs will read the file and split the lines to get maps between
// paired v4 and v6 resolvers, for printing formatted data later
func getResolverPairs(
	v4ToV6, v6ToV4 map[string]string,
	path string,
) {
	resolverPairFile, err := os.Open(path)
	if err != nil {
		errorLogger.Fatalf("Error opening resolver pair file: %v\n", err)
	}
	scanner := bufio.NewScanner(resolverPairFile)

	for scanner.Scan() {
		line := scanner.Text()
		splitLine := strings.Split(line, " ")
		var v4IP, v6IP net.IP
		v6IP = net.ParseIP(strings.TrimSpace(splitLine[0]))
		if splitLine[1] == " " {
			// this means there are double spaces between everything
			v4IP = net.ParseIP(strings.TrimSpace(splitLine[2]))
		} else {
			v4IP = net.ParseIP(strings.TrimSpace(splitLine[1]))
		}
		v4ToV6[v4IP.String()] = v6IP.String()
		v6ToV4[v6IP.String()] = v4IP.String()
	}
}

// resolverStats will go throug the results file and for each resolver will
// collect the number of control domains it got correct.
func resolverStats(
	resultsPath string,
	v4ToV6, v6ToV4 map[string]string,
	localResolvers map[string]ResolverStats,
) {
	resultsFile, err := os.Open(resultsPath)
	if err != nil {
		errorLogger.Fatalf("Error opening results file, %v\n", err)
	}
	defer resultsFile.Close()

	seenResolversToIDs := make(map[string]string)

	scanner := bufio.NewScanner(resultsFile)

	id := 1
	for scanner.Scan() {
		line := scanner.Text()
		var drr v4vsv6.DomainResolverResult
		json.Unmarshal([]byte(line), &drr)
		var strID string
		var AorB string
		if net.ParseIP(drr.ResolverIP).To4() != nil {
			AorB = "A"
		} else {
			AorB = "B"
		}
		// if we haven't seen this resolver yet...
		if sid, ok := seenResolversToIDs[drr.ResolverIP]; !ok {
			if AorB == "A" {
				// and we haven't seen it's pair...
				if sID, ok2 := seenResolversToIDs[v4ToV6[drr.ResolverIP]]; !ok2 {
					// use the next id
					strID = fmt.Sprintf("%d-%s", id, AorB)
					id++
				} else {
					// if we have seen it's pair...
					tID := strings.Split(sID, "-")[0]
					// use it
					strID = fmt.Sprintf("%s-%s", tID, AorB)
				}
			} else {
				// and we haven't seen it's pair...
				if sID, ok2 := seenResolversToIDs[v6ToV4[drr.ResolverIP]]; !ok2 {
					// use the next id
					strID = fmt.Sprintf("%d-%s", id, AorB)
					id++
				} else {
					// if we have seen it's pair...
					tID := strings.Split(sID, "-")[0]
					// use it
					strID = fmt.Sprintf("%s-%s", tID, AorB)
				}
			}
			seenResolversToIDs[drr.ResolverIP] = strID
		} else {
			strID = sid
		}
		if _, ok := localResolvers[strID]; !ok {
			localResolvers[strID] = ResolverStats{
				ID:              strID,
				ResolverIP:      drr.ResolverIP,
				ResolverCountry: drr.ResolverCountry,
				ControlCount:    0,
				BlockedDomains:  make(map[string]struct{}),
			}
		}
		rs := localResolvers[strID]
		if isControlDomain(drr) && drr.CorrectControlResolution {
			rs.ControlCount++
		} else if isCensorship(drr) {
			rs.BlockedDomains[drr.Domain+"-"+drr.RequestedAddressType] = struct{}{}
		}
		localResolvers[strID] = rs
	}
	for k := range localResolvers {
		resolvers[localResolvers[k].ResolverIP] = localResolvers[k]
	}
}

//writeQuestion6Output will write out to a file for each country code (in the
//correct directory) the JSON struct of Question6Output
func writeQuestion6Output(
	ccdtq6o CountryCodeDomainToQuestion6Output,
	dataType, fullFolderPath string,
) {
	for cc, dtq6o := range ccdtq6o {
		func() {
			ccFile, err := os.Create(filepath.Join(fullFolderPath, cc+".json"))
			if err != nil {
				errorLogger.Fatalf("Error creating country code file: %v\n", err)
			}
			defer ccFile.Close()

			for _, q6o := range dtq6o {
				bs, err := json.Marshal(q6o)
				if err != nil {
					errorLogger.Printf("Error Marshaling pair struct: %+v\n", q6o)
				}
				ccFile.Write(bs)
				ccFile.WriteString("\n")
			}
		}()
	}
}

// writeResolverStats will create a folder 'ResolverBlocks' with subdirectories
// of 'full' and 'passesControl' and write a file in each called
// resolver-blocks.json. This function will also create a map to keep track of
// how many resolvers censored domains in a country, then write it to a file.
func writeResolverStats(dataFolder string, localResolvers map[string]ResolverStats) {
	parentFolderPath := filepath.Join(dataFolder, "Question6")
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
		summaryFile, err := os.Create(filepath.Join(fullFolderPath, "resolver-blocks.json"))
		if err != nil {
			errorLogger.Fatalf("Error creating summary file: %v\n", err)
		}
		defer summaryFile.Close()

		ccdtq6o := make(CountryCodeDomainToQuestion6Output)
		for id := 0; id < len(localResolvers)/2; id++ {
			strIDA := fmt.Sprintf("%d-A", id+1)
			strIDB := fmt.Sprintf("%d-B", id+1)
			if localResolvers[strIDA].ResolverCountry != localResolvers[strIDB].ResolverCountry {
				// this comes from an issue where a single v4 resolvers get
				// associated with multiple v6 addresses, it will be fixed in
				// future runs, but needs to be kept for old runs
				infoLogger.Printf("\n%s - %s - %s\n%s - %s - %s\n", dataType, strIDA, localResolvers[strIDA].ResolverCountry, dataType, strIDB, localResolvers[strIDB].ResolverCountry)
				continue
			}
			if dataType == "passesControl" {
				if localResolvers[strIDA].ControlCount != len(controlDomains)*2 {
					continue
				}
				if localResolvers[strIDB].ControlCount != len(controlDomains)*2 {
					continue
				}
			}
			// if this is our first time seeing a country, make an output struct for it
			if ccdtq6o[localResolvers[strIDA].ResolverCountry] == nil {
				dtq6o := make(map[string]*Question6Output)
				ccdtq6o[localResolvers[strIDA].ResolverCountry] = dtq6o
			}
			dtq6o := ccdtq6o[localResolvers[strIDA].ResolverCountry]

			for domain := range localResolvers[strIDA].BlockedDomains {
				if dtq6o[domain] == nil {
					t := new(Question6Output)
					t.Domain = domain
					t.CountryCode = localResolvers[strIDA].ResolverCountry
					dtq6o[domain] = t
				}
				q6o := dtq6o[domain]

				q6o.V4CensoredCount++
				dtq6o[domain] = q6o
				ccdtq6o[localResolvers[strIDA].ResolverCountry] = dtq6o
			}

			dtq6o = ccdtq6o[localResolvers[strIDB].ResolverCountry]

			for domain := range localResolvers[strIDB].BlockedDomains {
				if dtq6o[domain] == nil {
					t := new(Question6Output)
					t.Domain = domain
					t.CountryCode = localResolvers[strIDB].ResolverCountry
					dtq6o[domain] = t
				}
				q6o := dtq6o[domain]

				q6o.V6CensoredCount++
				dtq6o[domain] = q6o
				ccdtq6o[localResolvers[strIDB].ResolverCountry] = dtq6o
			}

			bs, err := json.Marshal(localResolvers[strIDA])
			if err != nil {
				errorLogger.Printf("Error Marshaling pair struct: %+v\n", localResolvers[strIDA])
			}
			summaryFile.Write(bs)
			summaryFile.WriteString("\n")
			bs, err = json.Marshal(localResolvers[strIDB])
			if err != nil {
				errorLogger.Printf("Error Marshaling pair struct: %+v\n", localResolvers[strIDB])
			}
			summaryFile.Write(bs)
			summaryFile.WriteString("\n")
		}
		writeQuestion6Output(ccdtq6o, dataType, fullFolderPath)
	}
}

func Question6(args InterpretResultsFlags, v4ToV6, v6ToV4 map[string]string) {
	getResolverPairs(v4ToV6, v6ToV4, args.ResolverFile)

	resolvers = make(map[string]ResolverStats)
	localResolvers := make(map[string]ResolverStats) // this is only used for Question 6
	infoLogger.Println(
		"Reading results file to get basic resolver stats: IP, Country, and " +
			"how many control domains it successfully resolved, and what domains it blocked",
	)
	resolverStats(args.ResultsFile, v4ToV6, v6ToV4, localResolvers)
	infoLogger.Println("Writing resolver blocks to file and grouping data by country code.")
	writeResolverStats(args.DataFolder, localResolvers)
}
