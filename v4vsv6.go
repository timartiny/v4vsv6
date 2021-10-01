package v4vsv6

// AddressResult will store information about a specific IP address.
type AddressResult struct {
	IP          string `json:"ip,omitempty"`
	AddressType string `json:"address_type,omitempty"`
	Domain      string `json:"domain"`
	SupportsTLS bool   `json:"supports_tls,omitempty"`
	Timestamp   string `json:"timestamp,omitempty"`
	Error       string `json:"error,omitempty"`
}

// DomainResolverResult stores information on how a particular resolver
// responded to queries for a particular domain, including A and AAAA record
// requests
type DomainResolverResult struct {
	Domain               string           `json:"domain"`
	ResolverIP           string           `json:"resolver_ip"`
	ResolverCountry      string           `json:"resolver_country"`
	RequestedAddressType string           `json:"requested_address_type"`
	AResults             []*AddressResult `json:"a_results,omitempty"`
	AAAAResults          []*AddressResult `json:"aaaa_results,omitempty"`
}

// AppendAResults will take a slice of AddressResults and add non-duplicates to
// the AResults and return the slice, not updating the current AResults
func (drr *DomainResolverResult) AppendAResults(newARs []*AddressResult) []*AddressResult {
	ret := drr.AResults

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

// AppendAAAAResults will take a slice of AddressResults and add non-duplicates
// to the AAAAResults and return the slice, not updating the current AAAAResults
func (drr *DomainResolverResult) AppendAAAAResults(newARs []*AddressResult) []*AddressResult {
	ret := drr.AAAAResults

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
