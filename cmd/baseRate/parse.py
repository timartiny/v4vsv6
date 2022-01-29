
import json
import sys
from collections import defaultdict
import pycountry



# Each of these is {"US": [count1, count2, ...], ...
# Where countN is the number of domains of that resource type blocked at a given resolver
v4A = defaultdict(list)
v4AAAA = defaultdict(list)
v6A = defaultdict(list)
v6AAAA = defaultdict(list)
nResolvers = defaultdict(int)


for line in sys.stdin.readlines():
    o = json.loads(line)
    is_v4 = 'A' in o['id']
    domains = o['blocked_domains'].keys()
    country = o['resolver_country']

    Acount = 0
    AAAAcount = 0
    for domain in domains:
        if domain.endswith('-A'):
            Acount += 1
        elif domain.endswith('-AAAA'):
            AAAAcount += 1
        else:
            print('Error parsing domain "%s" from %s' % (domain, line))

    nResolvers[country] += 1

    if is_v4:
        v4A[country].append(Acount)
        v4AAAA[country].append(AAAAcount)
    else:
        v6A[country].append(Acount)
        v6AAAA[country].append(AAAAcount)

N = 714 # jq 'select(.has_v4 and .has_v6 and .has_v4_tls and .has_v6_tls).domain' satellite-full-details-jan-24.json -r | wc -l

# just some countries pycountry is weird about/has long names/etc...
customCountry = {'KR': 'South Korea', 'RU': 'Russia', 'VN': 'Vietnam'}
print('Country  resolvers  v4/A   v4/AAAA     v6/A    v6/AAAA')
for country, resolvers in sorted(nResolvers.items(), key=lambda x: x[1], reverse=True):

    resolvers /= 2  # resolver pairs
    country_name = pycountry.countries.get(alpha_2=country).name.split(',')[0]
    if country in customCountry:
        country_name = customCountry[country]
    try:
        v4Aavg = 100*sum(v4A[country]) / (N*len(v4A[country]))
        v4AAAAavg = 100*sum(v4AAAA[country]) / (N*len(v4AAAA[country]))
        v6Aavg = 100*sum(v6A[country]) / (N*len(v6A[country]))
        v6AAAAavg = 100*sum(v6AAAA[country]) / (N*len(v6AAAA[country]))

        cs = '%s (%s)' % (country_name, country)
        cs = cs.ljust(20)

        print('%s  &  % 4d  & %.1f\\%% &   %.1f\\%%  &   %.1f\\%% &   %.1f\\%% \\\\' % \
            (cs, resolvers, v4Aavg, v4AAAAavg, v6Aavg, v6AAAAavg))
    except ZeroDivisionError as e:
        print('%s   (incomplete) %d    %d/%d   %d/%d   %d/%d   %d/%d' % \
            (country, resolvers,
            sum(v4A[country]), N*len(v4A[country]),
            sum(v4AAAA[country]), N*len(v4AAAA[country]),
            sum(v6A[country]), N*len(v6A[country]),
            sum(v6AAAA[country]), N*len(v6AAAA[country])))

