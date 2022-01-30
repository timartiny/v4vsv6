
import sys
import json

#v4AAAA = defaultdict(int)
#v6AAAA = defaultdict(int)
domA = {}
domAAAA = {}

for line in sys.stdin.readlines():

    o = json.loads(line)
    domain = o['domain']
    v4 = o['v4_censored_count']
    v6 = o['v6_censored_count']

    if v4 > 100 and v6 > 100:
        if (v4-v6) > 20:
            print('%s +%d' % (domain, (v4-v6)))
        if (v4-v6) < -20:
            print('%s %d' % (domain, (v4-v6)))
