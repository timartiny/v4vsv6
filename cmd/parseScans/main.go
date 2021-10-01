package main

import (
	"bufio"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/alexflint/go-arg"
	"github.com/timartiny/v4vsv6"
	"github.com/zmap/zgrab2"
)

var (
	infoLogger  *log.Logger
	errorLogger *log.Logger
)

type ParseScansFlags struct {
	V4ARaw                  string `arg:"--v4-a-raw,required" help:"(Required) Path to the file containing the ZDNS results for A records from resolvers with v4 addresses" json:"v4_a_raw"`
	ResolverCountryCodeFile string `arg:"--resolver-country-code,required" help:"(Required) Path to the file with triplets of v6 address, v4 address, country code, to mark country code of resolvers." json:"resolver_country_code"`
	OutputFile              string `arg:"--output-file,required" help:"(Required) Path to write out the JSON resolver-domain-ip-tls structs" json:"output_file"`
	ATLSFile                string `arg:"--a-tls-file,required" help:"(Required) Path to the file containing the Zgrab2 scan output for TLS certificates using v4 addresses" json:"a_tls_file"`
	AAAATLSFile             string `arg:"--aaaa-tls-file,required" help:"(Required) Path to the file containing the Zgrab2 scan output for TLS certificates using v6 addresses" json:"aaaa_tls_file"`
}

type DomainResolverResultMap map[string]*v4vsv6.DomainResolverResult
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
func getResolverCountryCodeMap(rccm map[string]string, path string) {
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
		splitLine := strings.Split(line, "  ")
		countryCode := strings.TrimSpace(splitLine[2])
		ipv6Addr := strings.TrimSpace(splitLine[0])
		ipv4Addr := strings.TrimSpace(splitLine[1])
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
		// infoLogger.Printf(
		// 	"This results has NOERROR and no answers, domain: %s, "+
		// 		"resolver: %s\n",
		// 	domainName,
		// 	resolverStr,
		// )
		// keys := make([]string, len(dataMap))

		// i := 0
		// for k := range dataMap {
		// 	keys[i] = k
		// 	i++
		// }
		// sort.Strings(keys)
		// infoLogger.Printf("The data sections are: %v\n", keys)
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

// writeDomainResolverResults will read in ZDNS scan results and will write out
// info on the resolver, domain to be resolved, for which record, and the
// results to the provided file
func writeDomainResolverResults(
	ditarm DomainIPToAddressResultMap,
	rccm map[string]string,
	zdnsPath, outPath, resultType string,
) {
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

		results := getAddressResultFromZDNS(zdnsLine, resultType)

		// 	domainName := zdnsLine.Name
		// 	dataMap := zdnsLine.Data.(map[string]interface{})
		// 	resolverStr := strings.Split(dataMap["resolver"].(string), ":")[0]
		// 	key := domainName + "-" + resolverStr
		// 	drr := new(v4vsv6.DomainResolverResult)
		// 	if _, ok := drrm[key]; ok {
		// 		drr = drrm[key]
		// 	} else {
		// 		drr.Domain = domainName
		// 		drr.ResolverIP = resolverStr
		// 		if _, ok := rccm[resolverStr]; !ok {
		// 			errorLogger.Printf(
		// 				"resolver %s is not in resolver country code map!\n",
		// 				resolverStr,
		// 			)
		// 		}
		// 		drr.ResolverCountry = rccm[resolverStr]
		// 	}

		// 	if resultType == "A" {
		// 		drr.AResults = drr.AppendAResults(results)
		// 	} else if resultType == "AAAA" {
		// 		drr.AAAAResults = drr.AppendAAAAResults(results)
		// 	} else {
		// 		errorLogger.Fatalf(
		// 			"Invalid resultType: %s, use \"A\" or \"AAAA\"\n",
		// 			resultType,
		// 		)
		// 	}
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

// updateAddressResults will read into memory the results of a Zgrab2 scan and
// store the conclusions in AddressResults indexed by domain-ip
func updateAddressResults(ditarm DomainIPToAddressResultMap, path string) {
	tlsResultsFile, err := os.Open(path)
	if err != nil {
		errorLogger.Fatalf("error opening %s: %v\n", path, err)
	}
	defer tlsResultsFile.Close()

	scanner := bufio.NewScanner(tlsResultsFile)

	var numLines int
	for scanner.Scan() {
		var zgrabResult zgrab2.Grab
		l := scanner.Text()
		numLines++
		err = json.Unmarshal([]byte(l), &zgrabResult)
		if err != nil {
			errorLogger.Printf("error unmarshaling line: %s, err: %v\n", l, err)
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
		ar.SupportsTLS = verifyTLS(tlsScanResponse, zgrabResult.Domain)
		// use tmpIP to ensure same formatting of IP in key
		key := ar.Domain + "-" + tmpIP.String()
		if old, ok := ditarm[key]; ok {
			errorLogger.Printf("key: %s already seen\n", key)
			errorLogger.Printf("new.IP: %s, old.IP: %s\n", ar.IP, old.IP)
			errorLogger.Printf(
				"new.AddressType: %s, old.AddressType: %s\n",
				ar.AddressType,
				old.AddressType,
			)
			errorLogger.Printf(
				"new.Domain: %s, old.Domain: %s\n",
				ar.Domain,
				old.Domain,
			)
			errorLogger.Printf(
				"new.SupportsTLS: %t, old.SupportsTLS: %t\n",
				ar.SupportsTLS,
				old.SupportsTLS,
			)
			errorLogger.Printf(
				"new.Error: %s, old.Error: %s\n",
				ar.Error,
				old.Error,
			)
		}
		ditarm[key] = ar
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

	args := setupArgs()

	domainIPToAddressResultsMap := make(DomainIPToAddressResultMap)
	infoLogger.Printf(
		"Loading in TLS data from v4 addresses from %s\n",
		args.ATLSFile,
	)
	updateAddressResults(domainIPToAddressResultsMap, args.ATLSFile)
	infoLogger.Printf(
		"domainIPToAddressResultMap has %d entries\n",
		len(domainIPToAddressResultsMap),
	)

	infoLogger.Printf(
		"Loading in TLS data from v6 addresses from %s\n",
		args.AAAATLSFile,
	)
	updateAddressResults(domainIPToAddressResultsMap, args.AAAATLSFile)
	infoLogger.Printf(
		"domainIPToAddressResultMap has %d entries\n",
		len(domainIPToAddressResultsMap),
	)

	infoLogger.Printf(
		"Creating resolver -> country code map from %s\n",
		args.ResolverCountryCodeFile,
	)
	resolverCountryCodeMap := make(map[string]string)
	getResolverCountryCodeMap(
		resolverCountryCodeMap,
		args.ResolverCountryCodeFile,
	)
	infoLogger.Printf(
		"Writing resolvers (with v4 addresses) requesting A records data to %s\n",
		args.OutputFile,
	)
	writeDomainResolverResults(
		domainIPToAddressResultsMap,
		resolverCountryCodeMap,
		args.V4ARaw,
		"A",
		args.OutputFile,
	)
	// keys := make([]string, len(domainResolverResultMap))

	// i := 0
	// for k := range domainResolverResultMap {
	// 	keys[i] = k
	// 	i++
	// }
	// sort.Strings(keys)
	// infoLogger.Printf(
	// 	"Sample results for: %s: %+v\n",
	// 	keys[0],
	// 	domainResolverResultMap[keys[0]],
	// )
}
