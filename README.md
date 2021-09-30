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

`v4_cartesian_A_lookups.json`: 2.7 GB
```
real 10027.13
user 3328.90
sys 998.26
```

`v4_cartesian_AAAA_lookups.json`: 2.9 GB
```
Missing time data
```

`v6_cartesian_A_lookups.json`: 2.5 GB
```
real 14387.00
user 3083.54
sys 988.57
```

`v6_cartesian_AAAA_lookups.json`: 2.7 GB
```
real 14580.41
user 3184.37
sys 1014.58
```

The v6 lookups need to come from a v6 address. ZDNS does not automatically
select the v6 address of the machine, you need to manually enter it.

## Parse ZDNS data

The first ZDNS command took 1 hour 10 minutes on zbuff, and generated 2.7G of
data. A lot of it is repeated information, due to asking a lot of resolvers for
the same domain records.

A future step will require performing a TLS certificate lookup on all of the
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








