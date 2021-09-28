package v4vsv6

// AddressResult will store information about a specific IP address.
type AddressResult struct {
	IP          string `json:"ip,omitempty"`
	AddressType string `json:"address_type,omitempty"`
	Domain      string `json:"domain"`
	SupportsTLS bool   `json:"supports_tls,omitempty"`
	Timestamp   string `json:"timestamp"`
	Error       string `json:"error,omitempty"`
}

// DomainResolverResult stores information on how a particular resolver
// responded to queries for a particular domain, including A and AAAA record
// requests
type DomainResolverResult struct {
	Domain          string          `json:"domain"`
	ResolverIP      string          `json:"resolver_ip"`
	ResolverCountry string          `json:"resolver_country"`
	AResults        []AddressResult `json:"a_results,omitempty"`
	AAAAResults     []AddressResult `json:"aaaa_results,omitempty"`
}
