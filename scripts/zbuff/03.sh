#! /usr/bin/env bash

. ./variables.sh

echo "Make sure to grab the ${DATESTR}-v6.pcap file from the v6 NS before running this."
echo "Matching v6 IPs to v4 IPs from PCAP"
date
tcpdump -n -r ${OUTPUTFOLDER}/${DATESTR}-v6.pcap | python3 /home/timartiny/v6censorship/probe-dns/data/match.py 6to4 > ${OUTPUTFOLDER}/${DATESTR}-v6-to-v4
echo "Removing duplicate resolvers"
grep -v ',' ${OUTPUTFOLDER}/${DATESTR}-v6-to-v4 > ${OUTPUTFOLDER}/${DATESTR}-v6-to-v4-single-resolvers
echo "Applying Country codes"
python3 /home/timartiny/v6censorship/probe-dns/data/cc.py ${OUTPUTFOLDER}/${DATESTR}-v6-to-v4-single-resolvers > ${OUTPUTFOLDER}/${DATESTR}-v6-to-v4-single-resolvers-country-tmp
echo "Removing mismatching Country Codes"
grep -v '!!' ${OUTPUTFOLDER}/${DATESTR}-v6-to-v4-single-resolvers-country-tmp | grep -v 'None' | grep -v 'missing' > ${OUTPUTFOLDER}/${DATESTR}-v6-to-v4-single-resolvers-country
echo "Finding IPs that show up on multiple lines"
cat ${OUTPUTFOLDER}/${DATESTR}-v6-to-v4-single-resolvers-country | awk '{print $1}' | sort | uniq -d > ${OUTPUTFOLDER}/${DATESTR}-v6-to-v4-dup-v6
cat ${OUTPUTFOLDER}/${DATESTR}-v6-to-v4-single-resolvers-country | awk '{print $2}' | sort | uniq -d > ${OUTPUTFOLDER}/${DATESTR}-v6-to-v4-dup-v4
echo "Removing the duplicated IPs"
grep -vF -f ${OUTPUTFOLDER}/${DATESTR}-v6-to-v4-dup-v6 ${OUTPUTFOLDER}/${DATESTR}-v6-to-v4-single-resolvers-country > ${OUTPUTFOLDER}/${DATESTR}-v6-to-v4-single-resolvers-country-tmp
grep -vF -f ${OUTPUTFOLDER}/${DATESTR}-v6-to-v4-dup-v4 ${OUTPUTFOLDER}/${DATESTR}-v6-to-v4-single-resolvers-country-tmp > ${OUTPUTFOLDER}/${DATESTR}-v6-to-v4-single-resolvers-country
echo "Sorting the IPs and cleanup"
sort ${OUTPUTFOLDER}/${DATESTR}-v6-to-v4-single-resolvers-country > ${OUTPUTFOLDER}/${DATESTR}-v6-to-v4-single-resolvers-country-sorted
rm ${OUTPUTFOLDER}/${DATESTR}-v6-to-v4-single-resolvers-country-tmp
date
echo "Before running 04.sh make sure to start pcaping on v4 Name Server"

