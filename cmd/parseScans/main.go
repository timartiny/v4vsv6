package main

import (
	"bufio"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/alexflint/go-arg"
	"github.com/timartiny/v4vsv6"
	"github.com/zmap/zgrab2"
)

var (
	infoLogger          *log.Logger
	errorLogger         *log.Logger
	v4ControlDomToIPMap map[string]net.IP
	v6ControlDomToIPMap map[string]net.IP
)

type ParseScansFlags struct {
	Day        int    `arg:"--day,required" help:"(Required) The day of the experiment, will be used to determine which files to read and which fields to update" json:"day"`
	DataFolder string `arg:"--data-folder,required" help:"(Required) The folder to read data from and write to" json:"data_folder"`
	Repeats    bool   `arg:"--repeats" help:"Whether to look for repeat TLS connections or not" json:"repeats"`
	DateString string `arg:"--date-string,required" help:"(Required) The date string present in data files" json:"date_string"`
	Verbose    bool   `arg:"--verbose,-v" help:"Whether to add extra printing for debugging" json:"verbose"`
	// V4ARaw                  string `arg:"--v4-a-raw,required" help:"(Required) Path to the file containing the ZDNS results for A records from resolvers with v4 addresses" json:"v4_a_raw"`
	// V4AAAARaw               string `arg:"--v4-aaaa-raw,required" help:"(Required) Path to the file containing the ZDNS results for AAAA records from resolvers with v4 addresses" json:"v4_aaaa_raw"`
	// V6ARaw                  string `arg:"--v6-a-raw,required" help:"(Required) Path to the file containing the ZDNS results for A records from resolvers with v6 addresses" json:"v6_a_raw"`
	// V6AAAARaw               string `arg:"--v6-aaaa-raw,required" help:"(Required) Path to the file containing the ZDNS results for AAAA records from resolvers with v6 addresses" json:"v6_aaaa_raw"`
	// ResolverCountryCodeFile string `arg:"--resolver-country-code,required" help:"(Required) Path to the file with triplets of v6 address, v4 address, country code, to mark country code of resolvers." json:"resolver_country_code"`
	// OutputFile              string `arg:"--output-file,required" help:"(Required) Path to write out the JSON resolver-domain-ip-tls structs" json:"output_file"`
	// ATLSFile                string `arg:"--a-tls-file,required" help:"(Required) Path to the file containing the Zgrab2 scan output for TLS certificates using v4 addresses" json:"a_tls_file"`
	// AAAATLSFile             string `arg:"--aaaa-tls-file,required" help:"(Required) Path to the file containing the Zgrab2 scan output for TLS certificates using v6 addresses" json:"aaaa_tls_file"`
	// RepeatATLSFile          string `arg:"--repeat-a-tls-file" help:"Path to the file containing the Zgrab2 scan output for TLS certificates using v4 addresses, repeat file to work around rate limits" json:"repeat_a_tls_file"`
	// RepeatAAAATLSFile       string `arg:"--repeat-aaaa-tls-file" help:"Path to the file containing the Zgrab2 scan output for TLS certificates using v6 addresses, repeat file to work around rate limits" json:"repeat_aaaa_tls_file"`
}

// type DomainResolverResultMap map[string]*v4vsv6.DomainResolverResult
type DomainIPToAddressResultMap map[string]*v4vsv6.AddressResult

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

func setupArgs() ParseScansFlags {
	var ret ParseScansFlags
	arg.MustParse(&ret)

	return ret
}

// getResolverCountryCodeMap will read in the file of v6, v4, country code and
// create a mapping for each resolver IP to which country code is listed.
func getResolverCountryCodeMap(rccm map[string]string, path string, wg *sync.WaitGroup) {
	defer wg.Done()
	resolverFile, err := os.Open(path)
	if err != nil {
		errorLogger.Fatalf("error opening %s: %v\n", path, err)
	}
	defer resolverFile.Close()

	scanner := bufio.NewScanner(resolverFile)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "!!") {
			// We aren't using resolvers where the country code for v6 and v4
			// differ
			continue
		}
		splitLine := strings.Split(line, " ")
		var countryCode, ipv6Addr, ipv4Addr string
		ipv6Addr = strings.TrimSpace(splitLine[0])
		if splitLine[1] == " " {
			// this means there are double spaces between everything
			ipv4Addr = strings.TrimSpace(splitLine[2])
			countryCode = strings.TrimSpace(splitLine[4])
		} else {
			ipv4Addr = strings.TrimSpace(splitLine[1])
			countryCode = strings.TrimSpace(splitLine[2])
		}
		rccm[ipv6Addr] = countryCode
		rccm[ipv4Addr] = countryCode
	}
}

// getAddressResultFromZDNS will take a ZDNSResult, collect all the answers
// given and return all of the AddressResult entries in the mapping. If no
// address is provided it will return an AddressResult with the error part
// filled out
func getAddressResultFromZDNS(
	zdnsLine ZDNSResult,
	ditarm DomainIPToAddressResultMap,
) AddressResults {
	ret := make(AddressResults, 0)
	domainName := zdnsLine.Name
	dataMap := zdnsLine.Data.(map[string]interface{})
	resolverStr := dataMap["resolver"].(string)
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
		tmpIP := net.ParseIP(zdnsAnswer.Answer)
		if tmpIP == nil {
			errorLogger.Printf(
				"Got an Invalid IP from ZDNS: %s\n",
				zdnsAnswer.Answer,
			)
			errorLogger.Printf(
				"Came from resolver: %s, for domain: %s\n",
				resolverStr,
				domainName,
			)
			continue
		}
		ar, ok := ditarm[domainName+"-"+tmpIP.String()]
		if !ok {
			errorLogger.Printf("Got a ZDNS result that wasn't sent to Zgrab2!!\n")
			errorLogger.Printf(
				"Domain: %s, resolver: %s, answer: %s\n",
				domainName,
				resolverStr,
				tmpIP.String(),
			)
		}
		ret = append(ret, ar)
	}

	if len(ret) == 0 {
		singleAnswer := new(v4vsv6.AddressResult)
		singleAnswer.Domain = domainName
		singleAnswer.Error = "No A/AAAA records returned"
		ret = append(ret, singleAnswer)

	}

	return ret
}

// writeDomainResolverResults will write a particular DomainResolverResult to
// the provided file, first turning it into JSON after it receives it from the
// channel
func writeDomainResolverResults(
	drrChan <-chan *v4vsv6.DomainResolverResult,
	path string,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	outFile, err := os.Create(path)
	if err != nil {
		errorLogger.Fatalf("Error creating output file: %s, %v\n", path, err)
	}
	defer outFile.Close()

	for drr := range drrChan {
		bs, err := json.Marshal(drr)
		if err != nil {
			errorLogger.Printf("Error marshaling a drr: %v\n", err)
		}
		_, err = outFile.Write(bs)
		if err != nil {
			errorLogger.Printf("Error writing bytes of drr to file: %v\n", err)
		}
		_, err = outFile.WriteString("\n")
		if err != nil {
			errorLogger.Printf("Error writing newline to file: %v\n", err)
		}
	}
}

// isCensorship will read through a slice of AddressResults and return true if
// all of the Answers returned fail to support TLS, if any one does then no
// censorship.
func isCensorship(drr v4vsv6.DomainResolverResult, day int) bool {
	var results []*v4vsv6.AddressResult
	switch day {
	case 1:
		results = drr.Day1Results
	case 2:
		results = drr.Day1Results
	case 3:
		results = drr.Day3Results
	default:
		errorLogger.Fatalf("Invalid Day provided: %d, must be 1-3\n", day)
	}
	if len(results) == 0 || results[0] == nil {
		return true
	}

	for _, ar := range results {
		if ar.SupportsTLS {
			return false
		}
	}

	return true
}

// createThenWriteDomainResolverResults will read in ZDNS scan results and will
// write out info on the resolver, domain to be resolved, for which record, and
// the results to the provided file
func createThenWriteDomainResolverResults(
	ditarm DomainIPToAddressResultMap,
	rccm map[string]string,
	zdnsPath, resultType string,
	drrChan chan<- *v4vsv6.DomainResolverResult,
	day int,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	zdnsFile, err := os.Open(zdnsPath)
	if err != nil {
		errorLogger.Fatalf("error opening %s: %v\n", zdnsPath, err)
	}
	defer zdnsFile.Close()

	scanner := bufio.NewScanner(zdnsFile)

	for scanner.Scan() {
		line := scanner.Text()
		var zdnsLine ZDNSResult
		json.Unmarshal([]byte(line), &zdnsLine)

		results := getAddressResultFromZDNS(zdnsLine, ditarm)

		domainName := zdnsLine.Name
		dataMap := zdnsLine.Data.(map[string]interface{})
		resolverFullStr := dataMap["resolver"].(string)
		var resolverStr string
		if strings.Count(resolverFullStr, ":") == 1 {
			resolverStr = strings.Split(resolverFullStr, ":")[0]
		} else {
			resolverStr = strings.Split(
				strings.Split(resolverFullStr, "]")[0],
				"[",
			)[1]
		}
		drr := new(v4vsv6.DomainResolverResult)
		drr.Domain = domainName
		drr.ResolverIP = resolverStr
		if _, ok := rccm[resolverStr]; !ok {
			errorLogger.Printf(
				"resolver %s is not in resolver country code map!\n",
				resolverStr,
			)
		}
		drr.ResolverCountry = rccm[resolverStr]
		drr.RequestedAddressType = resultType
		switch day {
		case 1:
			drr.Day1Results = results
		case 2:
			drr.Day2Results = results
		case 3:
			drr.Day3Results = results
		default:
			errorLogger.Fatalf("Incorrect day passed: %d, must be 1-3\n", day)
		}
		if isControlDomain(drr.Domain) {
			for _, result := range results {
				if !result.ValidControlIP {
					drr.CorrectControlResolution = false
					break
				}
				drr.CorrectControlResolution = true
			}
		}
		if isCensorship(*drr, day) || isControlDomain(drr.Domain) {
			drr.CensoredQuery = true
		} else {
			drr.CensoredQuery = false
		}
		drrChan <- drr
	}
}

// verifyTLS will take a tls scan response and determine whether the information
// provided is a valid TLS cert for the given domainName at the time of the scan
func verifyTLS(tlsScanResponse zgrab2.ScanResponse, domainName string) bool {
	if tlsScanResponse.Status != "success" {
		// infoLogger.Printf("This results is a non-successful tls result: %s, %s\n", domainName, tlsScanResults.Status)
		return false
	}

	timestampString := tlsScanResponse.Timestamp
	timestamp, err := time.Parse(time.RFC3339, timestampString)
	if err != nil {
		errorLogger.Printf("Error parsing timestamp: %s\n", timestampString)
		return false
	}
	serverHandshakeInterface := tlsScanResponse.Result.(map[string]interface{})["handshake_log"].(map[string]interface{})
	serverCertificatesInterface := serverHandshakeInterface["server_certificates"].(map[string]interface{})
	leafCertificateInterface := serverCertificatesInterface["certificate"].(map[string]interface{})
	rawLeafCertificate := leafCertificateInterface["raw"].(string)

	decoded, err := base64.StdEncoding.DecodeString(string(rawLeafCertificate))
	if err != nil {
		errorLogger.Printf("base64.Decode of cert err: %v\n", err)
		return false
	}
	x509Cert, err := x509.ParseCertificate(decoded)
	if err != nil {
		errorLogger.Printf("x509.ParseCertificate of cert err: %v\n", err)
		errorLogger.Printf("decoded certificate: %v\n", decoded)
		return false
	}
	err = x509Cert.VerifyHostname(domainName)
	if err != nil {
		return false
	}

	certPool := x509.NewCertPool()
	var chain []interface{}
	if serverCertificatesInterface["chain"] != nil {
		chain = serverCertificatesInterface["chain"].([]interface{})
	}

	for ind, mInterface := range chain {
		raw := mInterface.(map[string]interface{})["raw"]
		chainDecoded, err := base64.StdEncoding.DecodeString(raw.(string))
		if err != nil {
			errorLogger.Printf("base64.Decode of chain ind %d err: %v\n", ind, err)
			continue
		}

		chainCert, err := x509.ParseCertificate(chainDecoded)
		if err != nil {
			errorLogger.Printf("x509.ParseCertificate for chain ind %d err: %v\n", ind, err)
			continue
		}
		certPool.AddCert(chainCert)
	}

	verifyOptions := x509.VerifyOptions{
		DNSName:       domainName,
		CurrentTime:   timestamp,
		Intermediates: certPool,
	}
	_, err = x509Cert.Verify(verifyOptions)
	return err == nil
}

// updateAddressResults will accept AddressResults from a channel then add them
// to the mapping, by their domain-ip as key. Will point out when something is
// already in the mapping.
func updateAddressResults(
	ditarm DomainIPToAddressResultMap,
	arChan <-chan *v4vsv6.AddressResult,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	for ar := range arChan {
		// tmpIP won't be invalid, already checked in createAddressResults
		tmpIP := net.ParseIP(ar.IP)
		key := ar.Domain + "-" + tmpIP.String()
		if oldAR, ok := ditarm[key]; ok {
			// the important bit here is whether the address supports TLS, and
			// we repeat scans, so if a previous scan supported TLS keep it, if
			// it didn't use the new one
			if oldAR.SupportsTLS {
				continue
			} else {
				ditarm[key] = ar
			}
		} else {
			ditarm[key] = ar
		}
	}
}

// isControlDomain will check if dom is in a list of control domains or not.
func isControlDomain(dom string) bool {
	controls := []string{"v4vsv6.com", "test1.v4vsv6.com", "test2.v4vsv6.com"}

	for _, cDom := range controls {
		if dom == cDom {
			return true
		}
	}

	return false
}

// verifyControlDomain will check whether the IP corresponds to the listed
// domain, this only works for hardcoded control domains, this function assumes
// the domain has already been tested as a control domain
func verifyControlDomain(ar v4vsv6.AddressResult) bool {

	if ar.AddressType == "A" {
		if v4ControlDomToIPMap[ar.Domain].String() == net.ParseIP(ar.IP).String() {
			return true
		}
	} else if ar.AddressType == "AAAA" {
		if v6ControlDomToIPMap[ar.Domain].String() == net.ParseIP(ar.IP).String() {
			return true
		}
	} else {
		errorLogger.Printf("Invalid Address Type given: %v\n", ar.AddressType)
	}

	return false
}

// createAddressResults will read into memory the results of a Zgrab2 scan and
// pass the conclusions in AddressResults to a channel to be indexed by
// domain-ip
func createAddressResults(
	path string,
	arChan chan<- *v4vsv6.AddressResult,
	verbose bool,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	tlsResultsFile, err := os.Open(path)
	if err != nil {
		errorLogger.Fatalf("error opening %s: %v\n", path, err)
	}
	var numLines int
	defer tlsResultsFile.Close()
	scanner := bufio.NewScanner(tlsResultsFile)

	// future scans can have duplicated attempts for the same TLS IP, and domain
	// to check for timeouts. To avoid parsing unnecessary lines (like if we
	// have already verified an IP supports TLS for a given domain) we keep a
	// mapping, and only parse a line if we haven't seen the domain-ip before or
	// if the domain-ip didn't support TLS last time.
	nonDuplicationMap := make(map[string]bool)
	// only used with verbose, so minor slow down
	nextVerboseTime := time.Now().Add(30 * time.Second)

	for scanner.Scan() {
		var zgrabResult zgrab2.Grab
		l := scanner.Text()
		numLines++
		if verbose && time.Now().After(nextVerboseTime) {
			infoLogger.Printf("Read in %d lines of %s\n", numLines, path)
			nextVerboseTime = time.Now().Add(30 * time.Second)
		}
		err = json.Unmarshal([]byte(l), &zgrabResult)
		if err != nil {
			errorLogger.Printf("error unmarshaling line: %s, err: %v\n", l, err)
			continue
		}
		if nonDuplicationMap[zgrabResult.Domain+"-"+zgrabResult.IP] {
			// we've seen this IP/domain before and found it supports TLS, no need to check the retries
			continue
		}
		ar := new(v4vsv6.AddressResult)
		ar.Domain = zgrabResult.Domain
		ar.IP = zgrabResult.IP
		tmpIP := net.ParseIP(ar.IP)
		if tmpIP != nil {
			if tmpIP.To4() == nil {
				ar.AddressType = "AAAA"
			} else {
				ar.AddressType = "A"
			}
		} else {
			errorLogger.Printf("Got an invalid IP: %s\n", ar.IP)
		}
		tlsScanResponse, ok := zgrabResult.Data["tls"]
		if !ok {
			errorLogger.Printf(
				"No \"tls\" section for %s, %s\n",
				zgrabResult.Domain,
				zgrabResult.IP,
			)
		}
		ar.Timestamp = tlsScanResponse.Timestamp
		if isControlDomain(ar.Domain) {
			ar.ValidControlIP = verifyControlDomain(*ar)

			nonDuplicationMap[ar.Domain+"-"+ar.IP] = ar.ValidControlIP
		} else {
			ar.SupportsTLS = verifyTLS(tlsScanResponse, zgrabResult.Domain)
			nonDuplicationMap[ar.Domain+"-"+ar.IP] = ar.SupportsTLS
		}
		arChan <- ar
	}

	infoLogger.Printf("Read %d lines from %s\n", numLines, path)
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
	v4ControlDomToIPMap = make(map[string]net.IP)
	v6ControlDomToIPMap = make(map[string]net.IP)
	v4ControlDomToIPMap["v4vsv6.com"] = net.ParseIP("192.12.240.40")
	v4ControlDomToIPMap["test1.v4vsv6.com"] = net.ParseIP("1.1.1.1")
	v4ControlDomToIPMap["test2.v4vsv6.com"] = net.ParseIP("2.2.2.2")
	v6ControlDomToIPMap["v4vsv6.com"] = net.ParseIP("2620:18f:30:4100::2")
	v6ControlDomToIPMap["test1.v4vsv6.com"] = net.ParseIP("1111:1111:1111:1111:1111:1111:1111:1111")
	v6ControlDomToIPMap["test2.v4vsv6.com"] = net.ParseIP("2222:2222:2222:2222:2222:2222:2222:2222")

	args := setupArgs()

	domainIPToAddressResultsMap := make(DomainIPToAddressResultMap)
	addressResultsChan := make(chan *v4vsv6.AddressResult, 100)
	domainResolverResultChan := make(chan *v4vsv6.DomainResolverResult, 100)
	var createAddressResultsWG sync.WaitGroup
	var resolverCountryCodeMapWG sync.WaitGroup
	var updateARWG sync.WaitGroup
	var drrWriteWG sync.WaitGroup
	var createAndWriteDomainResolverResultWG sync.WaitGroup

	updateARWG.Add(1)
	go updateAddressResults(
		domainIPToAddressResultsMap,
		addressResultsChan,
		&updateARWG,
	)

	aTLSFile := filepath.Join(
		args.DataFolder,
		fmt.Sprintf("A_tls_lookups_%s_day%d.json", args.DateString, args.Day),
	)
	infoLogger.Printf(
		"Loading in TLS data from v4 addresses from %s\n",
		aTLSFile,
	)

	createAddressResultsWG.Add(1)
	go createAddressResults(
		aTLSFile,
		addressResultsChan,
		args.Verbose,
		&createAddressResultsWG,
	)

	aaaaTLSFile := filepath.Join(
		args.DataFolder,
		fmt.Sprintf("AAAA_tls_lookups_%s_day%d.json", args.DateString, args.Day),
	)
	infoLogger.Printf(
		"Loading in TLS data from v6 addresses from %s\n",
		aaaaTLSFile,
	)
	createAddressResultsWG.Add(1)
	go createAddressResults(
		aaaaTLSFile,
		addressResultsChan,
		args.Verbose,
		&createAddressResultsWG,
	)

	resolverCountryCodeFile := filepath.Join(
		args.DataFolder,
		fmt.Sprintf("%s-single-resolvers-country-correct-sorted", args.DateString),
	)
	infoLogger.Printf(
		"Creating resolver -> country code map from %s\n",
		resolverCountryCodeFile,
	)
	resolverCountryCodeMap := make(map[string]string)
	resolverCountryCodeMapWG.Add(1)
	go getResolverCountryCodeMap(
		resolverCountryCodeMap,
		resolverCountryCodeFile,
		&resolverCountryCodeMapWG,
	)

	infoLogger.Println("Waiting for AddressResults to be created")
	createAddressResultsWG.Wait()
	if args.Repeats {
		repeatATLSFile := filepath.Join(
			args.DataFolder,
			fmt.Sprintf(
				"A_retry_tls_lookups_%s_day%d.json",
				args.DateString,
				args.Day,
			),
		)
		infoLogger.Printf(
			"Loading in repeat TLS data from v4 addresses from %s\n",
			repeatATLSFile,
		)

		createAddressResultsWG.Add(1)
		go createAddressResults(
			repeatATLSFile,
			addressResultsChan,
			args.Verbose,
			&createAddressResultsWG,
		)
		repeatAAAATLSFile := filepath.Join(
			args.DataFolder,
			fmt.Sprintf(
				"AAAA_retry_tls_lookups_%s_day%d.json",
				args.DateString,
				args.Day,
			),
		)
		infoLogger.Printf(
			"Loading in repeat TLS data from v6 addresses from %s\n",
			repeatAAAATLSFile,
		)
		createAddressResultsWG.Add(1)
		go createAddressResults(
			repeatAAAATLSFile,
			addressResultsChan,
			args.Verbose,
			&createAddressResultsWG,
		)
	}

	if args.Repeats {
		// wait for any optional runs of createAddressResults
		infoLogger.Println("Waiting for any repeat TLS scan results")
		createAddressResultsWG.Wait()
	}
	close(addressResultsChan)
	infoLogger.Println("Waiting for last second updates to Address Results")
	updateARWG.Wait()
	infoLogger.Printf(
		"domainIPToAddressResultMap has %d entries\n",
		len(domainIPToAddressResultsMap),
	)
	infoLogger.Println("Waiting resolver country codes to be filled in")
	resolverCountryCodeMapWG.Wait()

	outputFile := filepath.Join(
		args.DataFolder,
		fmt.Sprintf("%s-domain-resolver-results.json", args.DateString),
	)
	infoLogger.Printf("Writing DomainResolverResults to %s\n", outputFile)
	drrWriteWG.Add(1)
	go writeDomainResolverResults(domainResolverResultChan, outputFile, &drrWriteWG)

	v4ARawFile := filepath.Join(
		args.DataFolder,
		fmt.Sprintf(
			"v4_cartesian_A_lookups_%s_day%d.json",
			args.DateString,
			args.Day,
		),
	)
	infoLogger.Printf("Reading v4 A DNS lookups from %s\n", v4ARawFile)
	createAndWriteDomainResolverResultWG.Add(1)
	go createThenWriteDomainResolverResults(
		domainIPToAddressResultsMap,
		resolverCountryCodeMap,
		v4ARawFile,
		"A",
		domainResolverResultChan,
		args.Day,
		&createAndWriteDomainResolverResultWG,
	)

	v4AAAARawFile := filepath.Join(
		args.DataFolder,
		fmt.Sprintf(
			"v4_cartesian_AAAA_lookups_%s_day%d.json",
			args.DateString,
			args.Day,
		),
	)
	infoLogger.Printf("Reading v4 AAAA DNS lookups from %s\n", v4AAAARawFile)
	// createAndWriteDomainResolverResultWG.Add(1)
	// go createThenWriteDomainResolverResults(
	// 	domainIPToAddressResultsMap,
	// 	resolverCountryCodeMap,
	// 	v4AAAARawFile,
	// 	"AAAA",
	// 	domainResolverResultChan,
	// 	&createAndWriteDomainResolverResultWG,
	// )

	v6ARawFile := filepath.Join(
		args.DataFolder,
		fmt.Sprintf(
			"v6_cartesian_A_lookups_%s_day%d.json",
			args.DateString,
			args.Day,
		),
	)
	infoLogger.Printf("Reading v6 A DNS lookups from %s\n", v6ARawFile)
	// createAndWriteDomainResolverResultWG.Add(1)
	// go createThenWriteDomainResolverResults(
	// 	domainIPToAddressResultsMap,
	// 	resolverCountryCodeMap,
	// 	v6ARawFile,
	// 	"A",
	// 	domainResolverResultChan,
	// 	&createAndWriteDomainResolverResultWG,
	// )

	v6AAAARawFile := filepath.Join(
		args.DataFolder,
		fmt.Sprintf(
			"v6_cartesian_AAAA_lookups_%s_day%d.json",
			args.DateString,
			args.Day,
		),
	)
	infoLogger.Printf("Reading v6 AAAA DNS lookups from %s\n", v6AAAARawFile)

	// createAndWriteDomainResolverResultWG.Add(1)
	// go createThenWriteDomainResolverResults(
	// 	domainIPToAddressResultsMap,
	// 	resolverCountryCodeMap,
	// 	v6AAAARawFile,
	// 	"AAAA",
	// 	domainResolverResultChan,
	// 	&createAndWriteDomainResolverResultWG,
	// )

	// infoLogger.Println(
	// 	"Waiting for DomainResolverResults to be created and written",
	// )
	createAndWriteDomainResolverResultWG.Wait()
	close(domainResolverResultChan)
	drrWriteWG.Wait()
}
