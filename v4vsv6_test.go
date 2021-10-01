package v4vsv6

import (
	"fmt"
	"testing"
)

// TestAppendResults will test DomainResolverResult.AppendResults to ensure it
// has the correct length of return values as well as there being no duplicates
func TestAppendAResults(t *testing.T) {
	var drr DomainResolverResult
	drr.Domain = "fake-domain"
	ars := make([]*AddressResult, 0)
	for i := 0; i < 4; i++ {
		ar := new(AddressResult)
		ar.IP = "1.1.1." + fmt.Sprint(i)
		ar.Domain = "fake-domain"
		ars = append(ars, ar)
	}
	drr.Results = ars

	newArs := make([]*AddressResult, 0)
	for i := 0; i < 1; i++ {
		ar := new(AddressResult)
		ar.IP = "1.1.0." + fmt.Sprint(i)
		ar.Domain = "fake-domain"
		newArs = append(newArs, ar)
	}

	newAs := drr.AppendResults(newArs)
	if len(newAs) != 5 {
		t.Logf("newAs should have length 5, instead has length: %d\n", len(newAs))
		t.Logf("entries of newAs are:\n")
		for _, ar := range newAs {
			t.Logf("%+v\n", ar)
		}
		t.Fatalf("")
	}
	drr.Results = newAs

	oldArs := make([]*AddressResult, 0)
	for i := 0; i < 4; i++ {
		ar := new(AddressResult)
		ar.IP = "1.1.1." + fmt.Sprint(i)
		ar.Domain = "fake-domain"
		oldArs = append(oldArs, ar)
	}

	oldAs := drr.AppendResults(oldArs)
	if len(oldAs) != len(drr.Results) {
		t.Fatalf("Appending old AddressResults shouldn't add anythign new\n")
	}

}
