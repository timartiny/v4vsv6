#! /usr/bin/env bash
. ./variables.sh
/home/timartiny/RipeProbe/querylist --v4_dns $OUTPUTFOLDER/satellite-A-$DATESTR.json --v6_dns $OUTPUTFOLDER/satellite-AAAA-$DATESTR.json  --v4_tls $OUTPUTFOLDER/satellite-zgrab-A-$DATESTR.json --v6_tls $OUTPUTFOLDER/satellite-zgrab-AAAA-$DATESTR.json --citizen_lab_directory /home/timartiny/test-lists/lists/ --out_file $OUTPUTFOLDER/satellite-full-details-$DATESTR.json
