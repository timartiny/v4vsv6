#! /usr/bin/env bash

. ./variables.sh

/home/timartiny/v4vsv6/error_test.py $OUTPUTFOLDER/A_tls_lookups_$DATESTR.json /data/timartiny/v4vsv6/GeoLite2-ASN.mmdb $OUTPUTFOLDER/${DATESTR}_A_asn_data 3 $OUTPUTFOLDER/A-retry-list > $OUTPUTFOLDER/A-timeout-output
/home/timartiny/v4vsv6/error_test.py $OUTPUTFOLDER/AAAA_tls_lookups_$DATESTR.json /data/timartiny/v4vsv6/GeoLite2-ASN.mmdb $OUTPUTFOLDER/${DATESTR}_AAAA_asn_data 3 $OUTPUTFOLDER/AAAA-retry-list > $OUTPUTFOLDER/AAAA-timeout-output
