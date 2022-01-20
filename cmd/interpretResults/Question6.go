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

type ResolverStats struct {
	ID              string   `json:"id"`
	ResolverIP      string   `json:"resovler_ip"`
	ResolverCountry string   `json:"resolver_country"`
	ControlCount    int      `json:"control_count"`
	BlockedDomains  []string `json:"blocked_domains"`
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
		splitLine := strings.Split(line, "  ")
		v4IP := net.ParseIP(splitLine[1])
		v6IP := net.ParseIP(splitLine[0])
		v4ToV6[v4IP.String()] = v6IP.String()
		v6ToV4[v6IP.String()] = v4IP.String()
	}

}

// resolverStats will go throug the results file and for each resolver will
// collect the number of control domains it got correct.
func resolverStats(resultsPath string, v4ToV6, v6ToV4 map[string]string) {
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
		if _, ok := resolvers[strID]; !ok {
			resolvers[strID] = ResolverStats{
				ID:              strID,
				ResolverIP:      drr.ResolverIP,
				ResolverCountry: drr.ResolverCountry,
				ControlCount:    0,
				BlockedDomains:  []string{},
			}
		}
		rs := resolvers[strID]
		if isControlDomain(drr) && drr.CorrectControlResolution {
			rs.ControlCount++
		} else if isCensorship(drr) {
			rs.BlockedDomains = append(rs.BlockedDomains, drr.Domain)
		}
		resolvers[strID] = rs
	}
}

// writeResolverStats will create a folder 'ResolverBlocks' with subdirectories
// of 'full' and 'passesControl' and write a file in each called
// resolver-blocks.json
func writeResolverStats(dataFolder string, resolvers map[string]ResolverStats) {
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

		for id := 0; id < len(resolvers)/2; id++ {
			strIDA := fmt.Sprintf("%d-A", id+1)
			strIDB := fmt.Sprintf("%d-B", id+1)
			if dataType == "passesControl" {
				if resolvers[strIDA].ControlCount != len(controlDomains)*2 {
					continue
				}
				if resolvers[strIDB].ControlCount != len(controlDomains)*2 {
					continue
				}
			}
			bs, err := json.Marshal(resolvers[strIDA])
			if err != nil {
				errorLogger.Printf("Error Marshaling pair struct: %+v\n", resolvers[strIDA])
			}
			summaryFile.Write(bs)
			summaryFile.WriteString("\n")
			bs, err = json.Marshal(resolvers[strIDB])
			if err != nil {
				errorLogger.Printf("Error Marshaling pair struct: %+v\n", resolvers[strIDB])
			}
			summaryFile.Write(bs)
			summaryFile.WriteString("\n")
		}
	}
}

func Question6(args InterpretResultsFlags, v4ToV6, v6ToV4 map[string]string) {
	getResolverPairs(v4ToV6, v6ToV4, args.ResolverFile)

	resolvers = make(map[string]ResolverStats)
	infoLogger.Println(
		"Reading results file to get basic resolver stats: IP, Country, and " +
			"how many control domains it successfully resolved, and what domains it blocked",
	)
	resolverStats(args.ResultsFile, v4ToV6, v6ToV4)
	infoLogger.Println("Writing data to file")
	writeResolverStats(args.DataFolder, resolvers)
}
