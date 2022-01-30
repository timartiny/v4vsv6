
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

    is_v4 = domain.endswith('-A')
    domain = domain.split('-')[0]
    if is_v4:
        domA[domain] = (v4, v6)
    else:
        domAAAA[domain] = (v4, v6)



AAAAnotA = []
AnotAAAA = []

for domain in domA.keys():
    v4A, v6A = domA[domain]
    v4AAAA, v6AAAA = domAAAA[domain]

    if v4AAAA > 160 and v6AAAA > 160 and v4A < 20 and v6A < 20:
        AAAAnotA.append(domain)
    if v4AAAA < 20 and v6AAAA < 20 and v4A > 160 and v6A > 160:
        AnotAAAA.append(domain)


print('blocked in AAAA but not A: %d domains' % len(AAAAnotA))
print('\n'.join(AAAAnotA))

print('blocked in A but not AAAA: %d domains' % len(AnotAAAA))
print('\n'.join(AnotAAAA))
