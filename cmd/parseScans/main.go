package main

import (
	"bufio"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"os"
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
	// V4ARaw                  string `arg:"--v4-a-raw,required" help:"(Required) Path to the file containing the ZDNS results for A records from resolvers with v4 addresses" json:"v4_a_raw"`
	// ResolverCountryCodeFile string `arg:"--resolver-country-code,required" help:"(Required) Path to the file with triplets of v6 address, v4 address, country code, to mark country code of resolvers." json:"resolver_country_code"`
	ATLSFile    string `arg:"--a-tls-file,required" help:"(Required) Path to the file containing the Zgrab2 scan output for TLS certificates using v4 addresses" json:"a_tls_file"`
	AAAATLSFile string `arg:"--aaaa-tls-file,required" help:"(Required) Path to the file containing the Zgrab2 scan output for TLS certificates using v6 addresses" json:"aaaa_tls_file"`
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

// func getResolverCountryCodeMap(rccm map[string]string, path string) {
// 	resolverFile, err := os.Open(path)
// 	if err != nil {
// 		errorLogger.Fatalf("error opening %s: %v\n", path, err)
// 	}
// 	defer resolverFile.Close()

// 	scanner := bufio.NewScanner(resolverFile)

// 	for scanner.Scan() {
// 		line := scanner.Text()
// 		if strings.Contains(line, "!!") {
// 			// We aren't using resolvers where the country code for v6 and v4
// 			// differ
// 			continue
// 		}
// 		splitLine := strings.Split(line, "  ")
// 		countryCode := strings.TrimSpace(splitLine[2])
// 		ipv6Addr := strings.TrimSpace(splitLine[0])
// 		ipv4Addr := strings.TrimSpace(splitLine[1])
// 		rccm[ipv6Addr] = countryCode
// 		rccm[ipv4Addr] = countryCode
// 	}

// }

// func getAddressResultFromZDNS(zdnsLine ZDNSResult, resultType string) AddressResults {
// 	ret := make(AddressResults, 0)
// 	domainName := zdnsLine.Name
// 	dataMap := zdnsLine.Data.(map[string]interface{})
// 	resolverStr := dataMap["resolver"].(string)
// 	// key := domainName + "-" + resolverStr
// 	if zdnsLine.Status != "NOERROR" {
// 		// had a DNS error, so we should put that here
// 		singleAnswer := new(v4vsv6.AddressResult)
// 		singleAnswer.Domain = domainName
// 		singleAnswer.Error = zdnsLine.Status + ", " + zdnsLine.Error
// 		ret = append(ret, singleAnswer)
// 		return ret
// 	}

// 	interfaceAnswers, ok := zdnsLine.Data.(map[string]interface{})["answers"]
// 	if !ok {
// 		// infoLogger.Printf(
// 		// 	"This results has NOERROR and no answers, domain: %s, "+
// 		// 		"resolver: %s\n",
// 		// 	domainName,
// 		// 	resolverStr,
// 		// )
// 		keys := make([]string, len(dataMap))

// 		i := 0
// 		for k := range dataMap {
// 			keys[i] = k
// 			i++
// 		}
// 		sort.Strings(keys)
// 		// infoLogger.Printf("The data sections are: %v\n", keys)
// 		singleAnswer := new(v4vsv6.AddressResult)
// 		singleAnswer.Domain = domainName
// 		singleAnswer.Error = "No DNS Answers"
// 		ret = append(ret, singleAnswer)
// 		return ret
// 	}
// 	zdnsAnswers := interfaceAnswers.([]interface{})
// 	for _, interfaceAnswer := range zdnsAnswers {
// 		tmpJSONString, _ := json.Marshal(interfaceAnswer)
// 		var zdnsAnswer ZDNSAnswer
// 		json.Unmarshal(tmpJSONString, &zdnsAnswer)
// 		if zdnsAnswer.Type != "A" && zdnsAnswer.Type != "AAAA" {
// 			continue
// 		}
// 		addressResult := new(v4vsv6.AddressResult)
// 		addressResult.Domain = domainName
// 		addressResult.IP = zdnsAnswer.Answer
// 		if zdnsAnswer.Type != resultType {
// 			infoLogger.Printf(
// 				"Got different answer Type (%s) compared to expected type"+
// 					" (%s). Domain: %s, resolver: %s\n",
// 				zdnsAnswer.Type,
// 				resultType,
// 				domainName,
// 				resolverStr,
// 			)
// 		}
// 		addressResult.AddressType = zdnsAnswer.Type
// 		ret = append(ret, addressResult)
// 	}

// 	return ret
// }

// func updateDomainResolverResults(
// 	drrm DomainResolverResultMap,
// 	rccm map[string]string,
// 	path,
// 	resultType string,
// ) {
// 	domainResolverResultsRaw, err := os.Open(path)
// 	if err != nil {
// 		errorLogger.Fatalf("error opening %s: %v\n", path, err)
// 	}
// 	defer domainResolverResultsRaw.Close()

// 	scanner := bufio.NewScanner(domainResolverResultsRaw)

// 	var lineNum int
// 	for scanner.Scan() {
// 		lineNum++
// 		if lineNum%10000 == 0 {
// 			infoLogger.Printf("On line %d\n", lineNum)
// 		}
// 		line := scanner.Text()
// 		var zdnsLine ZDNSResult
// 		json.Unmarshal([]byte(line), &zdnsLine)

// 		results := getAddressResultFromZDNS(zdnsLine, resultType)

// 		domainName := zdnsLine.Name
// 		dataMap := zdnsLine.Data.(map[string]interface{})
// 		resolverStr := strings.Split(dataMap["resolver"].(string), ":")[0]
// 		key := domainName + "-" + resolverStr
// 		drr := new(v4vsv6.DomainResolverResult)
// 		if _, ok := drrm[key]; ok {
// 			drr = drrm[key]
// 		} else {
// 			drr.Domain = domainName
// 			drr.ResolverIP = resolverStr
// 			if _, ok := rccm[resolverStr]; !ok {
// 				errorLogger.Printf(
// 					"resolver %s is not in resolver country code map!\n",
// 					resolverStr,
// 				)
// 			}
// 			drr.ResolverCountry = rccm[resolverStr]
// 		}

// 		if resultType == "A" {
// 			drr.AResults = drr.AppendAResults(results)
// 		} else if resultType == "AAAA" {
// 			drr.AAAAResults = drr.AppendAAAAResults(results)
// 		} else {
// 			errorLogger.Fatalf(
// 				"Invalid resultType: %s, use \"A\" or \"AAAA\"\n",
// 				resultType,
// 			)
// 		}

// 		drrm[key] = drr
// 	}
// }

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

	for scanner.Scan() {
		var zgrabResult zgrab2.Grab
		l := scanner.Text()
		json.Unmarshal([]byte(l), &zgrabResult)
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
		key := ar.Domain + "-" + ar.IP
		ditarm[key] = ar
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

	domainIPToAddressResultsMap := make(DomainIPToAddressResultMap)
	infoLogger.Printf(
		"Loading in TLS data from v4 addresses from %s\n",
		args.ATLSFile,
	)
	updateAddressResults(domainIPToAddressResultsMap, args.ATLSFile)
	infoLogger.Printf(
		"Loading in TLS data from v6 addresses from %s\n",
		args.AAAATLSFile,
	)
	updateAddressResults(domainIPToAddressResultsMap, args.ATLSFile)
	// infoLogger.Printf(
	// 	"Creating resolver -> country code map from %s\n",
	// 	args.ResolverCountryCodeFile,
	// )
	// resolverCountryCodeMap := make(map[string]string)
	// getResolverCountryCodeMap(
	// 	resolverCountryCodeMap,
	// 	args.ResolverCountryCodeFile,
	// )
	// infoLogger.Printf(
	// 	"Creating the domain resolver result map from v4-a-raw file: %s\n",
	// 	args.V4ARaw,
	// )
	// domainResolverResultMap := make(DomainResolverResultMap)
	// updateDomainResolverResults(domainResolverResultMap, resolverCountryCodeMap, args.V4ARaw, "A")
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
