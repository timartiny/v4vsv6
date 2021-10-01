# Parse Scans

This package will take in the ZDNS and ZGrab2 results and store combined results
in a file.

The usage is: 
```
Usage: parseScans --v4-a-raw V4-A-RAW --v4-aaaa-raw V4-AAAA-RAW --v6-a-raw V6-A-RAW --v6-aaaa-raw V6-AAAA-RAW --resolver-country-code RESOLVER-COUNTRY-CODE --output-file OUTPUT-FILE --a-tls-file A-TLS-FILE --aaaa-tls-file AAAA-TLS-FILE

Options:
  --v4-a-raw V4-A-RAW    (Required) Path to the file containing the ZDNS results for A records from resolvers with v4 addresses
  --v4-aaaa-raw V4-AAAA-RAW
                         (Required) Path to the file containing the ZDNS results for AAAA records from resolvers with v4 addresses
  --v6-a-raw V6-A-RAW    (Required) Path to the file containing the ZDNS results for A records from resolvers with v6 addresses
  --v6-aaaa-raw V6-AAAA-RAW
                         (Required) Path to the file containing the ZDNS results for AAAA records from resolvers with v6 addresses
  --resolver-country-code RESOLVER-COUNTRY-CODE
                         (Required) Path to the file with triplets of v6 address, v4 address, country code, to mark country code of resolvers.
  --output-file OUTPUT-FILE
                         (Required) Path to write out the JSON resolver-domain-ip-tls structs
  --a-tls-file A-TLS-FILE
                         (Required) Path to the file containing the Zgrab2 scan output for TLS certificates using v4 addresses
  --aaaa-tls-file AAAA-TLS-FILE
                         (Required) Path to the file containing the Zgrab2 scan output for TLS certificates using v6 addresses
  --help, -h             display this help and exit
```

There are a lot of options, all required, but straight forward.

The run took 20 minutes on my local machine and the output file was 7.6 GB of
data that looks like:
```
{"domain":"bbc.co.uk","resolver_ip":"2002:4022:4e04::4022:4e04","resolver_country":"CA","requested_address_type":"AAAA","results":[{"ip":"2a04:4e42::81","address_type":"AAAA","domain":"bbc.co.uk","supports_tls":true,"timestamp":"2021-09-30T10:22:27-06:00"},{"ip":"2a04:4e42:200::81","address_type":"AAAA","domain":"bbc.co.uk","supports_tls":true,"timestamp":"2021-09-30T10:22:27-06:00"},{"ip":"2a04:4e42:400::81","address_type":"AAAA","domain":"bbc.co.uk","supports_tls":true,"timestamp":"2021-09-30T10:22:27-06:00"},{"ip":"2a04:4e42:600::81","address_type":"AAAA","domain":"bbc.co.uk","supports_tls":true,"timestamp":"2021-09-30T10:22:27-06:00"}]}
{"domain":"bbc.co.uk","resolver_ip":"2002:aa34:7e25::aa34:7e25","resolver_country":"CA","requested_address_type":"AAAA","results":[{"ip":"2a04:4e42::81","address_type":"AAAA","domain":"bbc.co.uk","supports_tls":true,"timestamp":"2021-09-30T10:22:27-06:00"},{"ip":"2a04:4e42:200::81","address_type":"AAAA","domain":"bbc.co.uk","supports_tls":true,"timestamp":"2021-09-30T10:22:27-06:00"},{"ip":"2a04:4e42:400::81","address_type":"AAAA","domain":"bbc.co.uk","supports_tls":true,"timestamp":"2021-09-30T10:22:27-06:00"},{"ip":"2a04:4e42:600::81","address_type":"AAAA","domain":"bbc.co.uk","supports_tls":true,"timestamp":"2021-09-30T10:22:27-06:00"}]}
```

`parseScans` uses a few simultaneous goroutines so don't expect the output to be
in the same order between runs.

## Unusual Cases

Of particular note is that 354 AAAA record requests essentially returned an A
record. It returned an address of the form `::fff:146.112.61.104`, which ZGrab2
interprets as just `146.112.61.104`, meaning in rare case you will find lines
with `requested_address_type: AAAA` but in results you'll find IPv4 addresses.



