package v4vsv6

// AddressResult will store information about a specific IP address.
type AddressResult struct {
	IP             string `json:"ip,omitempty"`
	AddressType    string `json:"address_type,omitempty"`
	Domain         string `json:"domain"`
	SupportsTLS    bool   `json:"supports_tls,omitempty"`
	ValidControlIP bool   `json:"valid_control_ip,omitempty"`
	Timestamp      string `json:"timestamp,omitempty"`
	Error          string `json:"error,omitempty"`
}

// DomainResolverResult stores information on how a particular resolver
// responded to queries for a particular domain, including A and AAAA record
// requests
type DomainResolverResult struct {
	Domain                   string           `json:"domain"`
	ResolverIP               string           `json:"resolver_ip"`
	ResolverCountry          string           `json:"resolver_country"`
	RequestedAddressType     string           `json:"requested_address_type"`
	Day1Results              []*AddressResult `json:"day_1_results,omitempty"`
	Day2Results              []*AddressResult `json:"day_2_results,omitempty"`
	Day3Results              []*AddressResult `json:"day_3_results,omitempty"`
	CorrectControlResolution bool             `json:"correct_control_resolution"`
	CensoredQuery            bool             `json:"censored_query"`
}

// AppendResults will take a slice of AddressResults and add non-duplicates to
// the Results and return the slice, not updating the current Results
func (drr *DomainResolverResult) AppendResults(newARs []*AddressResult, day int) []*AddressResult {
	var ret []*AddressResult
	switch day {
	case 1:
		ret = drr.Day1Results
	case 2:
		ret = drr.Day2Results
	default:
		ret = drr.Day3Results
	}

	existingIPs := make(map[string]bool)

	for _, ar := range ret {
		existingIPs[ar.IP] = true
	}

	for _, ar := range newARs {
		if existingIPs[ar.IP] {
			// this IP already exists in ret, don't add it again
			continue
		}

		// here means the IP isn't in ret yet, so add it
		ret = append(ret, ar)
		existingIPs[ar.IP] = true
	}

	return ret
}
