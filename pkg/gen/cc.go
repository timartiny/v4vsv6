package gen

import (
	"bufio"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
)

// CCMap maps a string to a list of subnets. Here this maps Country codes to
// to the list of subnets allocated within that country.
type CCMap map[string][]*net.IPNet

// GetRandomSubnet uses the provided random reader to select a random subnet out
// of the set of subnets associated with the provided country code. Returns nil
// if country code is not in map
func (ccm *CCMap) GetRandomSubnet(r io.Reader, cc string) *net.IPNet {
	if ccm.contains(cc) == ErrNoSubnets {
		return nil
	}
	tmpSlice := make([]byte, 4)
	_, err := r.Read(tmpSlice)
	if err != nil {
		return nil
	}
	i := binary.BigEndian.Uint32(tmpSlice) % uint32(len((*ccm)[cc]))
	return (*ccm)[cc][i]
}

// GetRandomAddr uses the provided random reader to select a random address
// from a random subnet out of the set of subnets associated with the provided
// country code. Return nil if country code is not in map
func (ccm *CCMap) GetRandomAddr(r io.Reader, cc string) *net.IP {
	if ccm.contains(cc) == ErrNoSubnets {
		return nil
	}
	subnet := ccm.GetRandomSubnet(r, cc)
	return RandomAddr(r, subnet)
}


func (ccm *CCMap) contains(cc string) error {
	if _, ok := map[string][]*net.IPNet(*ccm)[cc]; !ok {
		return ErrNoSubnets
	}
	return nil
}

// CountryCodeMaps contains the CCMaps mapping country code to subnet
// allocations for both IPv4 and IPv6 subnet allocations.
type CountryCodeMaps struct {
	idMap map[int]string
	V4Map CCMap
	V6Map CCMap
}

// BuildCountryCodeMaps build the reverse map of country code to associated
// subnets
func BuildCountryCodeMaps(dbPath string) (*CountryCodeMaps, error) {

	idFile := dbPath + "GeoLite2-Country-Locations-en.csv"
	csvFile, _ := os.Open(idFile)
	reader := csv.NewReader(bufio.NewReader(csvFile))

	ccMap := &CountryCodeMaps{
		idMap: make(map[int]string, 0),
	}

	// Parse label line
	_, err := reader.Read()
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("Error parsing csv file '%s': Not enough content", idFile)
		}
		return nil, fmt.Errorf("Error parsing csv file'%s: %s", idFile, err)
	}

	for {
		line, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println(err)
			continue
		}
		geoID, err := strconv.Atoi(line[0])
		if err != nil {
			log.Println(err)
			continue
		}

		cc := line[4]
		if cc != "" {
			ccMap.idMap[geoID] = cc
		}
	}

	// Parse V4 Subnets.
	ccMap.V4Map, err = parseSubnetsCC(dbPath+"GeoLite2-Country-Blocks-IPv4.csv", ccMap.idMap)
	if err != nil {
		return nil, err
	}

	// Parse V6 Subnets.
	ccMap.V6Map, err = parseSubnetsCC(dbPath+"GeoLite2-Country-Blocks-IPv6.csv", ccMap.idMap)
	if err != nil {
		return nil, err
	}

	return ccMap, nil
}

func parseSubnetsCC(csvPath string, idMap map[int]string) (map[string][]*net.IPNet, error) {
	csvFile, _ := os.Open(csvPath)
	reader := csv.NewReader(bufio.NewReader(csvFile))
	subnetMap := make(map[string][]*net.IPNet, 0)

	// Parse label line
	_, err := reader.Read()
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("Error parsing csv file '%s': Not enough content", csvPath)
		}
		return nil, fmt.Errorf("Error parsing csv file '%s: %s", csvPath, err)
	}

	for {
		line, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println(err)
			continue
		}
		// registeredCCGeoID, err := strconv.Atoi(line[2])
		// if err != nil {
		// 	log.Println(err)
		// 	continue
		// }

		if line[2] == "" {
			continue
		}
		representedCCGeoID, err := strconv.Atoi(line[2])
		if err != nil {
			log.Println(err)
			continue
		}

		cc, ok := idMap[representedCCGeoID]
		if !ok {
			continue
		}

		_, network, err := net.ParseCIDR(line[0])
		if err != nil {
			log.Println(err)
			continue
		}

		// if _, ok := subnetMap[cc]; !ok {
		// 	subnetMap[cc] = []*net.IPNet{}
		// }

		subnetMap[cc] = append(subnetMap[cc], network)
	}

	return subnetMap, nil
}

// GetRandomAddr4 selects an IPv4 addresses at random with from subnets
// associated with a specific country code.
func (ccm *CountryCodeMaps) GetRandomAddr4(r io.Reader, cc string) (*net.IP, error) {
	if err := ccm.V4Map.contains(cc); err != nil {
		return nil, err
	}
	return ccm.V4Map.GetRandomAddr(r, cc), nil
}

// GetRandomAddr6 selects an IPv6 addresses at random with from subnets
// associated with a specific country code.
func (ccm *CountryCodeMaps) GetRandomAddr6(r io.Reader, cc string) (*net.IP, error) {
	if err := ccm.V6Map.contains(cc); err != nil {
		return nil, err
	}
	return ccm.V6Map.GetRandomAddr(r, cc), nil
}

// GetNRandomAddr4 selects N IPv4 addresses at random with no repeats from
// subnets associated with a specific country code.
func (ccm *CountryCodeMaps) GetNRandomAddr4(r io.Reader, cc string, n int) ([]*net.IP, error) {
	if err := ccm.V4Map.contains(cc); err != nil {
		return nil, err
	}
	addrs := make([]*net.IP, 0)

	for i := 0; len(addrs) < n; i++ {
		addr := ccm.V4Map.GetRandomAddr(r, cc)
		if addr == nil {
			continue
		}
		for _, a := range addrs {
			if a.String() == addr.String() {
				continue
			}
		}

		addrs = append(addrs, addr)
	}

	return addrs, nil
}

// GetNRandomAddr6 selects N IPv6 addresses at random with no repeats from
// subnets associated with a specific country code.
func (ccm *CountryCodeMaps) GetNRandomAddr6(r io.Reader, cc string, n int) ([]*net.IP, error) {
	if err := ccm.V6Map.contains(cc); err != nil {
		return nil, err
	}
	addrs := make([]*net.IP, 0)

	for i := 0; len(addrs) < n; i++ {
		addr := ccm.V6Map.GetRandomAddr(r, cc)
		if addr == nil {
			continue
		}
		for _, a := range addrs {
			if a.String() == addr.String() {
				continue
			}
		}

		addrs = append(addrs, addr)
	}

	return addrs, nil
}

// GetCCList returns a list of all country codes.
func (ccm *CountryCodeMaps) GetCCList() []string {
	j := 0
	countryCodes := make([]string, len(ccm.idMap))
	for _, cc := range ccm.idMap {
		countryCodes[j] = cc
		j++
	}
	sort.Strings(countryCodes)

	return countryCodes
}
