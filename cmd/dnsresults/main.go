package main

import (
	"bufio"
	"encoding/json"
	"log"
	"os"

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

func setupArgs() DNSResultsFlags {
	var ret DNSResultsFlags
	arg.MustParse(&ret)

	return ret
}

func updateDomainResolverResults(drrm DomainResolverResultMap, path string) {
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

		domainName := zdnsLine.Name

		interfaceAnswers, ok := zdnsLine.Data.(map[string]interface{})["answers"]
		if !ok {
			// infoLogger.Printf("This results has no answers, domain: %s\n", domainName)
			continue
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
			addressResult.AddressType = zdnsAnswer.Type
			errorLogger.Fatalf("%+v\n", addressResult)
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
	var domainResolverResultMap DomainResolverResultMap
	updateDomainResolverResults(domainResolverResultMap, args.V4ARaw)
}
