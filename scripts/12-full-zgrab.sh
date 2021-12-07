#! /usr/bin/env bash

. ./variables.sh

echo "Running TLS banner grab on A records"
date
time -p cat $OUTPUTFOLDER/A_ip_domain_list_$DATESTR.dat | /home/timartiny/zgrab2/zgrab2 --output-file $OUTPUTFOLDER/A_tls_lookups_$DATESTR.json --connections-per-host 3 tls
echo "Running TLS banner grab on AAAA records"
date
time -p cat $OUTPUTFOLDER/AAAA_ip_domain_list_$DATESTR.dat | /home/timartiny/zgrab2/zgrab2 --output-file $OUTPUTFOLDER/AAAA_tls_lookups_$DATESTR.json --connections-per-host 3 tls 
