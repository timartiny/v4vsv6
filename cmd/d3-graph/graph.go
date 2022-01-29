package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"sync"

	"github.com/alexflint/go-arg"
)

var (
	infoLogger  *log.Logger
	errorLogger *log.Logger
)

type GraphFlags struct {
	MaxEditDistance int  `arg:"-m,--max-edit-distance" help:"How far should links be created" default:"5" json:"max_edit_distance"`
	DiscardEmpty    bool `arg:"-e,--discard-empty" help:"Don't compare empty blocklists" default: "false" json:"discard_empty"`
	IncludeSingles  bool `arg:"-s,--include-single" help:"Include nodes that are unconnected from any other node" default: "false" json:"include_single"`
}

type Output struct {
	Nodes Nodes `json:"nodes"`
	Links Links `json:"links"`
}

type ResolverStats struct {
	ID              string              `json:"id"`
	ResolverIP      string              `json:"resovler_ip"`
	ResolverCountry string              `json:"resolver_country"`
	ControlCount    int                 `json:"control_count"`
	BlockedDomains  map[string]struct{} `json:"blocked_domains"`
}

type Node struct {
	Id    string `json:"id"`
	Value string `json:"value"`
	Group int    `json:"group"`
}

type Nodes []*Node

type NodeWithBlocklist struct {
	Id        string   `json:"id"`
	Blocklist []string `json:"blocklist"`
}

type Link struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Value  int    `json:"value"`
}

type Links []*Link

func setupArgs() GraphFlags {
	var ret GraphFlags
	arg.MustParse(&ret)

	return ret
}

func updateNodeMaps(nodes *Nodes, ntbl map[string][]string, lc <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	for line := range lc {
		var rs ResolverStats
		json.Unmarshal([]byte(line), &rs)
		n := new(Node)
		if net.ParseIP(rs.ResolverIP).To4() != nil {
			n.Group = 1
		} else {
			n.Group = 2
		}
		n.Value = "5" // default size, can change to larger/smaller if needed
		n.Id = rs.ID
		*nodes = append(*nodes, n)

		keys := make([]string, len(rs.BlockedDomains))
		i := 0
		for k := range rs.BlockedDomains {
			keys[i] = k
			i++
		}
		sort.Strings(keys)
		ntbl[rs.ID] = keys
	}
}

// levenshteinMin will compute the minimum of three integers.
func levenshteinMin(a, b, c uint) uint {
	if a <= b {
		if a <= c {
			return a
		} else {
			return c
		}
	} else {
		if b <= c {
			return b
		} else {
			return c
		}
	}
}

// levenshtein will take to slices of strings and determine the Levenshtein Edit
// Distance between them.
func levenshtein(a, b []string) uint {
	n := len(a)
	m := len(b)
	if n > m {
		return levenshtein(b, a)
	}

	current := make([]uint, n+1)
	previous := make([]uint, n+1)
	for i := uint(0); i < uint(len(current)); i++ {
		current[i] = i
	}
	for i := uint(1); i <= uint(m); i++ {
		copy(previous, current)
		current = make([]uint, n+1)
		current[0] = i
		for j := 1; j <= n; j++ {
			add, delete := previous[j]+1, current[j-1]+1
			change := previous[j-1]
			if a[j-1] != b[i-1] {
				change++
			}
			current[j] = levenshteinMin(add, delete, change)
		}
		copy(previous, current)
	}

	return current[n]
}

func updateLinkMap(links *Links, nonEmptyNodes map[string]bool, maxEditDistance int, discardEmpty bool, nc <-chan []NodeWithBlocklist, wg *sync.WaitGroup) {
	defer wg.Done()

	for ns := range nc {
		n1, n2 := ns[0], ns[1]
		if discardEmpty {
			if len(n1.Blocklist) == 0 || len(n2.Blocklist) == 0 {
				continue
			}
		}
		editDistance := levenshtein(n1.Blocklist, n2.Blocklist)
		if editDistance <= uint(maxEditDistance) {
			*links = append(*links, &Link{Source: n1.Id, Target: n2.Id, Value: maxEditDistance - int(editDistance)})

			nonEmptyNodes[n1.Id] = true
			nonEmptyNodes[n2.Id] = true

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
	var nodes Nodes
	var wg sync.WaitGroup
	nodeToBlockedList := make(map[string][]string)
	lineChan := make(chan string, 10)

	wg.Add(1)
	go updateNodeMaps(&nodes, nodeToBlockedList, lineChan, &wg)

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		lineChan <- line
	}
	close(lineChan)

	if err := scanner.Err(); err != nil {
		errorLogger.Fatalf("Error reading from stdin: %v\n", err)
	}
	wg.Wait()
	infoLogger.Printf("Got %d nodes, blocked domains from 1-A: %v\n", len(nodes), nodeToBlockedList["1-A"])

	var links Links
	nodesChan := make(chan []NodeWithBlocklist, 10)
	connectedNodeIds := make(map[string]bool)

	wg.Add(1)
	go updateLinkMap(&links, connectedNodeIds, args.MaxEditDistance, args.DiscardEmpty, nodesChan, &wg)

	keys := make([]string, 0, len(nodeToBlockedList))
	for k := range nodeToBlockedList {
		keys = append(keys, k)
	}

	for id1, k1 := range keys {
		for _, k2 := range keys[id1+1:] {
			n1 := NodeWithBlocklist{Id: k1, Blocklist: nodeToBlockedList[k1]}
			n2 := NodeWithBlocklist{Id: k2, Blocklist: nodeToBlockedList[k2]}
			nb := []NodeWithBlocklist{n1, n2}
			nodesChan <- nb
		}
	}
	close(nodesChan)

	wg.Wait()
	infoLogger.Printf("Got %d links\n", len(links))
	if len(links) > 0 {
		infoLogger.Printf("first link: %v\n", links[0])
	}

	var connectedNodes Nodes
	for _, node := range nodes {
		if _, ok := connectedNodeIds[node.Id]; ok || args.IncludeSingles {
			connectedNodes = append(connectedNodes, node)
		}
	}

	out := Output{Nodes: connectedNodes, Links: links}
	bs, err := json.MarshalIndent(&out, "", "  ")
	if err != nil {
		errorLogger.Fatalf("Error writing output to bytes: %v\n", err)
	}

	fmt.Printf("%s", bs)
}
