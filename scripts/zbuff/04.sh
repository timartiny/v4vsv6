#! /usr/bin/env bash

. ./variables.sh

echo "Probing resolvers found from zmap for our domain in a NS accessible only over IPv4"
echo "Make sure you set up PCAPing on the v4 NS"
date
time -p cat ${OUTPUTFOLDER}/${DATESTR}-v6-to-v4-single-resolvers-country-sorted | awk '{print $1}' | /home/timartiny/v6censorship/probe-dns/probe -domain v4.tlsfingerprint.io -source-ip "2620:18f:30:4100::2" -workers 1000 -prefix --v6-addresses > ${OUTPUTFOLDER}/${DATESTR}-v6.probe.out
date
echo "Grab the PCAP file from the v4 NS before running 05.sh"

