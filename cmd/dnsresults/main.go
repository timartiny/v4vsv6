package main

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"sort"

	"github.com/alexflint/go-arg"
	"github.com/timartiny/v4vsv6"
)

var (
	infoLogger  *log.Logger
	errorLogger *log.Logger
)

type DNSResultsFlags struct {
	V4ARaw string `arg:"--v4-a-raw,required" help:"(Required) Path to the file containing the ZDNS results for A records from resolvers with v4 addresses" required:"true" json:"v4_a_raw"`
}

type DomainResolverResultMap map[string]v4vsv6.DomainResolverResult

type ZDNSResult struct {
	AlteredName string        `json:"altered_name,omitempty" groups:"short,normal,long,trace"`
	Name        string        `json:"name,omitempty" groups:"short,normal,long,trace"`
	Nameserver  string        `json:"nameserver,omitempty" groups:"normal,long,trace"`
	Class       string        `json:"class,omitempty" groups:"long,trace"`
	AlexaRank   int           `json:"alexa_rank,omitempty" groups:"short,normal,long,trace"`
	Metadata    string        `json:"metadata,omitempty" groups:"short,normal,long,trace"`
	Status      string        `json:"status,omitempty" groups:"short,normal,long,trace"`
	Error       string        `json:"error,omitempty" groups:"short,normal,long,trace"`
	Timestamp   string        `json:"timestamp,omitempty" groups:"short,normal,long,trace"`
	Data        interface{}   `json:"data,omitempty" groups:"short,normal,long,trace"`
	Trace       []interface{} `json:"trace,omitempty" groups:"trace"`
}

type ZDNSAnswer struct {
	Ttl     uint32 `json:"ttl" groups:"ttl,normal,long,trace"`
	Type    string `json:"type,omitempty" groups:"short,normal,long,trace"`
	RrType  uint16 `json:"-"`
	Class   string `json:"class,omitempty" groups:"short,normal,long,trace"`
	RrClass uint16 `json:"-"`
	Name    string `json:"name,omitempty" groups:"short,normal,long,trace"`
	Answer  string `json:"answer,omitempty" groups:"short,normal,long,trace"`
}

type AddressResults []*v4vsv6.AddressResult

func setupArgs() DNSResultsFlags {
	var ret DNSResultsFlags
	arg.MustParse(&ret)

	return ret
}

func getAddressResultFromZDNS(zdnsLine ZDNSResult, resultType string) AddressResults {
	ret := make(AddressResults, 0)
	domainName := zdnsLine.Name
	dataMap := zdnsLine.Data.(map[string]interface{})
	resolverStr := dataMap["resolver"].(string)
	// key := domainName + "-" + resolverStr
	if zdnsLine.Status != "NOERROR" {
		// had a DNS error, so we should put that here
		singleAnswer := new(v4vsv6.AddressResult)
		singleAnswer.Domain = domainName
		singleAnswer.Error = zdnsLine.Status + ", " + zdnsLine.Error
		ret = append(ret, singleAnswer)
		return ret
	}

	interfaceAnswers, ok := zdnsLine.Data.(map[string]interface{})["answers"]
	if !ok {
		infoLogger.Printf(
			"This results has NOERROR and no answers, domain: %s, "+
				"resolver: %s\n",
			domainName,
			resolverStr,
		)
		keys := make([]string, len(dataMap))

		i := 0
		for k := range dataMap {
			keys[i] = k
			i++
		}
		sort.Strings(keys)
		infoLogger.Printf("The data sections are: %v\n", keys)
		singleAnswer := new(v4vsv6.AddressResult)
		singleAnswer.Domain = domainName
		singleAnswer.Error = "No DNS Answers"
		ret = append(ret, singleAnswer)
		return ret
	}
	zdnsAnswers := interfaceAnswers.([]interface{})
	for _, interfaceAnswer := range zdnsAnswers {
		tmpJSONString, _ := json.Marshal(interfaceAnswer)
		var zdnsAnswer ZDNSAnswer
		json.Unmarshal(tmpJSONString, &zdnsAnswer)
		if zdnsAnswer.Type != "A" && zdnsAnswer.Type != "AAAA" {
			continue
		}
		addressResult := new(v4vsv6.AddressResult)
		addressResult.Domain = domainName
		addressResult.IP = zdnsAnswer.Answer
		if zdnsAnswer.Type != resultType {
			infoLogger.Printf(
				"Got different answer Type (%s) compared to expected type"+
					" (%s). Domain: %s, resolver: %s\n",
				zdnsAnswer.Type,
				resultType,
				domainName,
				resolverStr,
			)
		}
		addressResult.AddressType = zdnsAnswer.Type
		ret = append(ret, addressResult)
	}

	return ret
}

func updateDomainResolverResults(drrm DomainResolverResultMap, path, resultType string) {
	domainResolverResultsRaw, err := os.Open(path)
	if err != nil {
		errorLogger.Fatalf("error opening %s: %v\n", path, err)
	}
	defer domainResolverResultsRaw.Close()

	scanner := bufio.NewScanner(domainResolverResultsRaw)

	for scanner.Scan() {
		line := scanner.Text()
		var zdnsLine ZDNSResult
		json.Unmarshal([]byte(line), &zdnsLine)
		// infoLogger.Printf("zdnsLine: %+v\n", zdnsLine)

		results := getAddressResultFromZDNS(zdnsLine, resultType)

		domainName := zdnsLine.Name
		dataMap := zdnsLine.Data.(map[string]interface{})
		resolverStr := dataMap["resolver"].(string)
		key := domainName + "-" + resolverStr
		var drr v4vsv6.DomainResolverResult
		if _, ok := drrm[key]; ok {
			drr = drrm[key]
		} else {
			drr.Domain = domainName
			drr.ResolverIP = resolverStr
		}

		if resultType == "A" {
			drr.AResults = drr.AppendAResults(results)
		} else if resultType == "AAAA" {
			drr.AAAAResults = drr.AppendAAAAResults(results)
		} else {
			errorLogger.Fatalf(
				"Invalid resultType: %s, use \"A\" or \"AAAA\"\n",
				resultType,
			)
		}
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
	infoLogger.Printf("v4-a-raw file: %s\n", args.V4ARaw)
	domainResolverResultMap := make(DomainResolverResultMap)
	updateDomainResolverResults(domainResolverResultMap, args.V4ARaw, "A")
}
