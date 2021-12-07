#! /usr/bin/env bash
. ./variables.sh
tcpdump -n -r $OUTPUTFOLDER/$DATESTR-v6.pcap | python3 /home/ewust/v6censorship/probe-dns/data/match.py 6to4 > $OUTPUTFOLDER/$DATESTR-v6-to-v4
cat $OUTPUTFOLDER/$DATESTR-v6-to-v4 | awk '{print $1}' | grep -F -f - $OUTPUTFOLDER/$DATESTR-v6-to-v4 | grep -v ',' > $OUTPUTFOLDER/$DATESTR-single-resolvers
python3 /home/timartiny/v6censorship/probe-dns/data/cc.py $OUTPUTFOLDER/$DATESTR-single-resolvers > $OUTPUTFOLDER/$DATESTR-single-resolvers-country-tmp
grep -v '!!' $OUTPUTFOLDER/$DATESTR-single-resolvers-country-tmp | grep -v 'None' | grep -v 'missing' > $OUTPUTFOLDER/$DATESTR-single-resolvers-country
sort -u $OUTPUTFOLDER/$DATESTR-single-resolvers-country > $OUTPUTFOLDER/$DATESTR-single-resolvers-country-sorted
