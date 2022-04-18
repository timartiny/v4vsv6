#! /usr/bin/env bash

. ./variables.sh

echo "Make sure you are PCAPing on the machine that hosts a NS for a v4 and v6 domain before continuing"
echo "Performing Preference Scan"
time -p cat ${OUTPUTFOLDER}/${DATESTR}-single-resolvers-country-sorted | awk '{print $1}' | /home/timartiny/v6censorship/probe-dns/probe -source-ip "2620:18f:30:4100::2" -domain both.v4vsv6.com -record A -workers 1000 > ${OUTPUTFOLDER}/${DATESTR}-v6-preference.out
time -p cat ${OUTPUTFOLDER}/${DATESTR}-single-resolvers-country-sorted | awk '{print $2}' | /home/timartiny/v6censorship/probe-dns/probe -source-ip 192.12.240.41 -domain both.v4vsv6.com -record A -workers 1000 > ${OUTPUTFOLDER}/${DATESTR}-v4-preference.out
date
echo "Stop PCAPing on machine with NS for v4 and v6 domain, then run 07.sh, PCAP will be needed for 12.sh"
