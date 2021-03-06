
# Bidirectional DNS Scanner

Send packets to addresses that should not respond on UDP 53 _FAST_.

* if they respond to controls - probably actuall resolvers by accident
* if they respond to others - bidirectional censorship

This file is meant to pair with the address generators in `cmd/generate_from_addrs` and `cmd/generate_from_subnets`.

## Usage

```txt
Usage of ./bidi:
  -domains string
        File with a list of domains to test (default "domains.txt")
  -iface string
        Interface to listen on (default "eth0")
  -laddr string
        Local address to send packets from - unset uses default interface.
  -qtype uint
        Type of Query to send (1 = A / 28 = AAAA) (default 1)
  -verbose
        Verbose prints sent/received DNS packets/info (default true)
  -wait duration
        Duration to wait for DNS response (default 5s)
  -workers uint
        Number worker threads (default 50)
```

So for example

```sh
cat may-11/generated_addr* | cut -d " " -f 1 | zblocklist -b /etc/zmap/blacklist.conf | sudo ./bidi -laddr "<local_addr>" -qtype 1  -workers 2000 -wait 5ms -iface enp1s0f0:0 > may-11/bidi_3.out 2>&1
```
