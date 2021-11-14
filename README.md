# V4 vs V6

This repo will determine differences between A and AAAA record requests from
resolvers across the world on domains the
[Satellite](https://censoredplanet.org/projects) has decided to perform DNS look
ups on.

## Creating ZDNS files
Our goal is to perform an A and AAAA record request on lots of domains and from
lots of resolvers. To facilitate this we will use
[ZDNS](https://github.com/zmap/zdns). Specifically by passing in
`<domain>,<resolver>` lines. 

Thus we first need to make a file containing those lines.

`./domain_resolver_pairs.py` will do that:

```
usage: domain_resolver_pairs.py [-h]
                                domain_json_file resolver_file
                                v4_cartesian_file v6_cartesian_file

positional arguments:
  domain_json_file   Path to the file containing JSON object on each domain
  resolver_file      Path to the file containing resolvers
  v4_cartesian_file  Path to the file to write the cartesian product, with v4
                     resolvers
  v6_cartesian_file  Path to the file to write the cartesian product, with v6
                     resolvers

optional arguments:
  -h, --help         show this help message and exit
```
```
./domain_resolver_pairs.py data/satellite-v4-and-v6-and-tls-sept22.json data/aug-30-2-single-resolvers-country-correct-sorted data/v4_cartesian_file data/v6_cartesian_file
```

## ZDNS

With the cartesian product of domains and resolvers added to files and grouped
by address type of the resolver you can run 4 different ZDNS calls:

```
cat data/v4_cartesian_file | ./zdns A --output-file data/v4_cartesian_A_lookups.json
cat data/v4_cartesian_file | ./zdns AAAA --output-file data/v4_cartesian_AAAA_lookups.json
cat data/v6_cartesian_file | ./zdns A --local-addr "<v6 address>" --output-file data/v6_cartesian_A_lookups.json
cat data/v6_cartesian_file | ./zdns AAAA --local-addr "<v6 address>"--output-file data/v6_cartesian_AAAA_lookups.json
```

The above commands took the following amounts of time, and created various
amounts of data:

The following are the stats from the latest run on Nov. 12
`v4_cartesian_A_lookups.json`: 2.8 GB
```
real 2695.44
user 3170.05
sys 706.42
```

`v4_cartesian_AAAA_lookups.json`: 3.1 GB
```
real 2462.11
user 3255.20
sys 687.10
```

`v6_cartesian_A_lookups.json`: 2.8 GB
```
real 2976.76
user 3077.58
sys 711.46
```

`v6_cartesian_AAAA_lookups.json`: 3.1 GB
```
real 2885.43
user 3159.38
sys 705.47
```

The v6 lookups need to come from a v6 address. ZDNS does not automatically
select the v6 address of the machine, you need to manually enter it.

Times for the v6 scans:
```
v6-A-Scan:
    real 3256.31
    user 1635.27
    sys 396.85
```

## Prepare for ZGrab2

The next step will require performing a TLS certificate lookup on all of the
answers provided. `ZGrab2` accepts input in the form of "`<ip address>,
<domain>`", so we want to make that list, while not adding any unnecessary
duplication. To make that list we run:

```
cat v4_cartesian_A_lookups.json | jq '.name as $name | .data.answers[]? | select(.type=="A") | "\(.answer), \($name)"' > tmp
sort -u tmp > v4_A_ip_domain_list.dat
# Now the AAAA record version
cat v4_cartesian_AAAA_lookups.json | jq -r '.name as $name | .data.answers[]? | select(.type=="AAAA") | "\(.answer), \($name)"' > tmp
sort -u tmp > v4_AAAA_ip_domain_list.dat
```

The `jq` command took just over a minute to run and made a file with 9.8M
lines, just under 300 MB.

The `sort` command took about 10 seconds and made a file 100K lines (480K lines
for v6), 3.5 MB (24 MB for v6 addresses).

One last simplification, there will be duplicates of "ip, domain" pairs
generated from v4 resolvers and v6 resolvers. So their lists should be combined
and sorted into only unique pairs:

```
cat v4_A_ip_domain_list.dat v6_A_ip_domain_list.dat > tmp
sort -u tmp > A_ip_domain_list.dat
# v6 version
cat v4_AAAA_ip_domain_list.dat v6_AAAA_ip_domain_list.dat > tmp
sort -u tmp > AAAA_ip_domain_list.dat
```

These are very quick and result in two files:

`A_ip_domain_list.dat`: 3.6MB with 120K lines

`AAAA_ip_domain_list.dat`: 28MB with 560K lines.

## ZGrab2 

Once the A and AAAA request files are made we can run two Zgrab2 commands:
```
cat A_ip_domain_list.dat | zgrab2 --output-file data/A_tls_lookups.json tls
cat AAAA_ip_domain_list.dat | zgrab2 --output-file data/AAAA_tls_lookups.json tls
```

`A_tls_lookups.json`: 2.2 GB
```
real 82.29
user 498.01
sys 22.25
```

`AAAA_tls_lookups.json`: 11 GB
```
real 547.18
user 2254.74
sys 102.45
```

## Parse Scans

Full README in the [directory](cmd/parseScan).

Sample usage:

```
cmd/parseScans$ go build -o parseScans main.go
cmd/parseScans$ ./parseScans --a-tls-file ../../data/A_tls_lookups_sept_30.json --aaaa-tls-file ../../data/AAAA_tls_lookups_sept_30.json --resolver-country-code ../../data/aug-30-2-single-resolvers-country-correct-sorted --v4-a-raw ../../data/v4_cartesian_A_lookups_sept_29.json --v4-aaaa-raw ../../data/v4_cartesian_AAAA_lookups_sept_29.json --v6-a-raw ../../data/v6_cartesian_A_lookups_sept_29.json --v6-aaaa-raw ../../data/v6_cartesian_AAAA_lookups_sept_29.json --output-file ../../data/domain-resolver-results.json
```

This run took 20 minutes on my laptop and generated an output file of 7.6 GB
formatted like:

```
{"domain":"bbc.co.uk","resolver_ip":"2002:4022:4e04::4022:4e04","resolver_country":"CA","requested_address_type":"AAAA","results":[{"ip":"2a04:4e42::81","address_type":"AAAA","domain":"bbc.co.uk","supports_tls":true,"timestamp":"2021-09-30T10:22:27-06:00"},{"ip":"2a04:4e42:200::81","address_type":"AAAA","domain":"bbc.co.uk","supports_tls":true,"timestamp":"2021-09-30T10:22:27-06:00"},{"ip":"2a04:4e42:400::81","address_type":"AAAA","domain":"bbc.co.uk","supports_tls":true,"timestamp":"2021-09-30T10:22:27-06:00"},{"ip":"2a04:4e42:600::81","address_type":"AAAA","domain":"bbc.co.uk","supports_tls":true,"timestamp":"2021-09-30T10:22:27-06:00"}]}
{"domain":"bbc.co.uk","resolver_ip":"2002:aa34:7e25::aa34:7e25","resolver_country":"CA","requested_address_type":"AAAA","results":[{"ip":"2a04:4e42::81","address_type":"AAAA","domain":"bbc.co.uk","supports_tls":true,"timestamp":"2021-09-30T10:22:27-06:00"},{"ip":"2a04:4e42:200::81","address_type":"AAAA","domain":"bbc.co.uk","supports_tls":true,"timestamp":"2021-09-30T10:22:27-06:00"},{"ip":"2a04:4e42:400::81","address_type":"AAAA","domain":"bbc.co.uk","supports_tls":true,"timestamp":"2021-09-30T10:22:27-06:00"},{"ip":"2a04:4e42:600::81","address_type":"AAAA","domain":"bbc.co.uk","supports_tls":true,"timestamp":"2021-09-30T10:22:27-06:00"}]}
```
