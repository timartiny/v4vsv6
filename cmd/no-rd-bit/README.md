# No RD Bit

No RD Bit will take a list of resolvers and a list of domains and perform `A`
and `AAAA` record requests to each resolver for each domain with the rd bit set to 0. It will then spit
out responses:

```
{"resolver":"201.140.112.174","domain":"v4vsv6.com","record":"A","r_code":0,"c_code":3,"explanation":"Resolver returned Additionals and/or Authorities"}
```

```
Usage: no-rd-bit --resolvers RESOLVERS --domains DOMAINS [--source-ip SOURCE-IP] [--threads THREADS] [--timeout TIMEOUT] --output OUTPUT

Options:
  --resolvers RESOLVERS
                         (Required) Path to file containing list of Resolvers to query
  --domains DOMAINS      (Required) Path to the file containing domains to issue A and AAAA record requests to
  --source-ip SOURCE-IP
                         Address to send queries from [default: 192.12.240.40]
  --threads THREADS      Number of goroutines to use for queries [default: 1000]
  --timeout TIMEOUT      Number of seconds to wait for DNS and TLS connections [default: 5]
  --output OUTPUT        (Required) Path to the file to save results to
  --help, -h             display this help and exit
```
## Censorship Codes
Each response will get labelled with a `c_code` for the result of the record
requests the options are:

* Unknown = 0

This is the default setting whenever a record request is made, this should only
show up in unusual circumstances.

* ResolverResolveError = 1

The resolver gave a non-zero `r_code`, meaning it had an error it reported to
us, you can see the `r_code` in the response

* ResolverDialError = 2

The no-rd-bit script failed to Dial the address to create a UDP socket, this
error might be on our end?

* ResolverReadError = 3

The Resolver didn't respond during the provided Timeout Window.

* ReturnedAdditionals = 4

The Resolver returned only Additionals (NSes) and Authorities, no Answers

* ReturnedInvalidRecord = 5

The Resolver returned at least one Answer, but when we followed up with a TLS
connection we did not get a valid TLS cert back from any Answer
    
* ReturnedValidRecord = 6

The Resolver returned at least one Answer, and when we followed up at least one
of the IPs returned a valid TLS certificate