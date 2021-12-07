#! /usr/bin/env bash
. ./variables.sh
cat $OUTPUTFOLDER/satellite-ip-dom-pair-$DATESTR-A.dat | /home/timartiny/zgrab2/zgrab2 -o $OUTPUTFOLDER/satellite-zgrab-A-$DATESTR.json tls
cat $OUTPUTFOLDER/satellite-ip-dom-pair-$DATESTR-AAAA.dat | /home/timartiny/zgrab2/zgrab2 -o $OUTPUTFOLDER/satellite-zgrab-AAAA-$DATESTR.json tls
