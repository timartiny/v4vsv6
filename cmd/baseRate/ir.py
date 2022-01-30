
import json
import sys
from collections import defaultdict
import pycountry
import math
from ipwhois import IPWhois
import pyasn

blockedv4 = defaultdict(set)    # {example.com: [id1, id3, ...]
blockedv6 = defaultdict(set)    # {example.com: [id1, id2, ..]
idv4 = {} # id => v4 addr
idv6 = {} # id => v6 addr

for line in sys.stdin.readlines():
    o = json.loads(line)
    is_v4 = 'A' in o['id']
    domains = o['blocked_domains'].keys()
    country = o['resolver_country']
    if o['control_count'] != 6:
        continue

    idx = o['id'].split('-')[0]


    if country != 'IR':
        continue

    if is_v4:
        idv4[idx] = o['resovler_ip']    # typo on purpose
    else:
        idv6[idx] = o['resovler_ip']    # typo on purpose

    for domain in domains:
        if is_v4:
            blockedv4[domain].add(idx)
        else:
            blockedv6[domain].add(idx)

N = 714 # jq 'select(.has_v4 and .has_v6 and .has_v4_tls and .has_v6_tls).domain' satellite-full-details-jan-24.json -r | wc -l

v4prefs = defaultdict(int)

for domain in blockedv4.keys():
    v4ids = blockedv4[domain]
    v6ids = blockedv6[domain]

    if (len(v4ids) - len(v6ids)) > 20:
        for idx in (v4ids - v6ids):
            v4prefs[idx] += 1


asn = pyasn.pyasn('/home/ewust/ipasn.20220130.0600.dat')
for idx,n in sorted(v4prefs.items(), key=lambda x: x[1], reverse=True):
    v4as = 0
    v6as = 0
    try:
        #v4as = IPWhois(idv4[idx]).lookup_whois()['asn']
        #v6as = IPWhois(idv6[idx]).lookup_whois()['asn']
        v4as = asn.lookup(idv4[idx])[0]
        print('%s %d %s %s   AS%s' % (idx, n, idv4[idx], idv6[idx], v4as))
    except:
        print('%s %d %s %s   (%s, %s) AS failed' % (idx, n, idv4[idx], idv6[idx], v4as, v6as))



