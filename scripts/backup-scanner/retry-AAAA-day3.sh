#! /usr/bin/env bash
. ./variables.sh
cat $OUTPUTFOLDER/AAAA-retry-list_day3 | /home/colorado/go/src/github.com/zmap/zgrab2/zgrab2 --output-file $OUTPUTFOLDER/AAAA_retry_tls_lookups_${DATESTR}_day3.json tls
