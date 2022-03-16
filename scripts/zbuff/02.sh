#! /usr/bin/env bash

. ./variables.sh

echo "Probing resolvers found from zmap for our domain in a NS accessible only over IPv6"
echo "Make sure you set up PCAPing on the v6 NS"
date
time -p /home/timartiny/v6censorship/probe-dns/probe -domain v6.tlsfingerprint.io -source-ip <local-ip-address-to-scan-from> -workers 1000 -prefix < ${OUTPUTFOLDER}/${DATESTR}-zmap.csv > ${OUTPUTFOLDER}/${DATESTR}-v4.probe.out
date 
echo "Grab the PCAP file from the v6 NS before running 03.sh"

