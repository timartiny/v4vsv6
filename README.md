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
                                domain_json_file resolver_file cartesian_file

positional arguments:
  domain_json_file  Path to the file containing JSON object on each domain
  resolver_file     Path to the file containing resolvers
  cartesian_file    Path to the file to write the cartesian product

optional arguments:
  -h, --help        show this help message and exit
```

Sample files are in the [data](data/) directory that can run this:

```
./domain_resolver_pairs.py data/satellite-v4-and-v6-and-tls-sept22.json data/aug-30-2-single-resolvers-country-correct-sorted data/cartesian_file
```