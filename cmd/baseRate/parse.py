
import json
import sys
from collections import defaultdict
import pycountry
import math



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

# takes v4A[country], v4AAAA[country], etc
# returns (avg, stdev, fc) where fc is a function that colors accordingly
def getMeta(A, B, C, D):
    #allSamples = v4A[country] + v4AAAA[country] + v6A[country] + v6AAAA[country]
    allSamples = A+B+C+D
    avg = 100*sum(allSamples) / (N*len(allSamples))
    sq = [((100*s/N)-avg)**2 for s in allSamples]
    stdev = math.sqrt(sum(sq) / len(sq))

    # format and color
    def fc(p):
        d = abs(p - avg)
        color = 'green'
        if p > avg:
            color = 'red'
        sds = stdev/4
        if d < sds:
            return '%.1f\\%%' % p    # no color
        for i in range(2,5):
            if d < sds*i:
                return '\cellcolor{%s%d} %.1f\\%%' % (color, i-2, p)
        return '\cellcolor{%s5} % .1f\\%%' % (color, p)

    return (avg, stdev, fc)






totResolvers = 0
# just some countries pycountry is weird about/has long names/etc...
customCountry = {'KR': 'South Korea', 'RU': 'Russia', 'VN': 'Vietnam'}
print('Country  resolvers  v4/A   v4/AAAA     v6/A    v6/AAAA')
goodCountries = []
for country, resolvers in sorted(nResolvers.items(), key=lambda x: x[1], reverse=True):

    resolvers /= 2  # resolver pairs
    totResolvers += resolvers
    country_name = pycountry.countries.get(alpha_2=country).name.split(',')[0]


    if resolvers >= 50:
        goodCountries.append(country)
    if country in customCountry:
        country_name = customCountry[country]
    try:
        v4Aavg = 100*sum(v4A[country]) / (N*len(v4A[country]))
        v4AAAAavg = 100*sum(v4AAAA[country]) / (N*len(v4AAAA[country]))
        v6Aavg = 100*sum(v6A[country]) / (N*len(v6A[country]))
        v6AAAAavg = 100*sum(v6AAAA[country]) / (N*len(v6AAAA[country]))

        avg, stdev, fc = getMeta(v4A[country], v4AAAA[country], v6A[country], v6AAAA[country])

        cs = '%s (%s)' % (country_name, country)
        cs = cs.ljust(20)
        print('%s  &  % 4d  & %s & %s & %s & %s \\\\  %% avg %.1f stdev %.1f' % \
            (cs, resolvers, fc(v4Aavg), fc(v4AAAAavg), fc(v6Aavg), fc(v6AAAAavg), avg, stdev))
    except ZeroDivisionError as e:
        print('%s   (incomplete) %d    %d/%d   %d/%d   %d/%d   %d/%d' % \
            (country, resolvers,
            sum(v4A[country]), N*len(v4A[country]),
            sum(v4AAAA[country]), N*len(v4AAAA[country]),
            sum(v6A[country]), N*len(v6A[country]),
            sum(v6AAAA[country]), N*len(v6AAAA[country])))



print('\\hline')

#goodCountries = v4A.keys()

totRes = sum([nResolvers[cc] for cc in goodCountries])/2

all_v4A = [d for cc in goodCountries for d in v4A[cc]]
all_v4AAAA = [d for cc in goodCountries for d in v4AAAA[cc]]
all_v6A = [d for cc in goodCountries for d in v6A[cc]]
all_v6AAAA = [d for cc in goodCountries for d in v6AAAA[cc]]

#tv4A = 100*sum([sum(v4A[cc]) for cc in goodCountries]) / (N*sum([len(v4A[cc]) for cc in goodCountries]))
#tv4AAAA = 100*sum([sum(v4AAAA[cc]) for cc in goodCountries]) / (N*sum([len(v4AAAA[cc]) for cc in goodCountries]))
#tv6A = 100*sum([sum(v6A[cc]) for cc in goodCountries]) / (N*sum([len(v6A[cc]) for cc in goodCountries]))
#tv6AAAA = 100*sum([sum(v6AAAA[cc]) for cc in goodCountries]) / (N*sum([len(v6AAAA[cc]) for cc in goodCountries]))
tv4A = 100*sum(all_v4A) / (N*len(all_v4A))
tv4AAAA = 100*sum(all_v4AAAA) / (N*len(all_v4AAAA))
tv6A = 100*sum(all_v6A) / (N*len(all_v6A))
tv6AAAA = 100*sum(all_v6AAAA) / (N*len(all_v6AAAA))

avg, stdev, fc = getMeta(all_v4A, all_v4AAAA, all_v6A, all_v6AAAA)

print('\\textbf{Global}            & \\textbf{% 5d} & \\textbf{%s} & \\textbf{%s} & \\textbf{%s} & \\textbf{%s} \\\\ %% avg %.1f stdev %.1f' % \
        (totRes, fc(tv4A), fc(tv4AAAA), fc(tv6A), fc(tv6AAAA), avg, stdev))



