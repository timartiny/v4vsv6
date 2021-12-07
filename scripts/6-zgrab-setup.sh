#! /usr/bin/env bash
. ./variables.sh
cat $OUTPUTFOLDER/satellite-A-$DATESTR.json | jq -r '.name as $name | .data.answers[]? | select(.type=="A") | "\(.answer), \($name)"' > $OUTPUTFOLDER/satellite-ip-dom-pair-$DATESTR-A.dat
cat $OUTPUTFOLDER/satellite-AAAA-$DATESTR.json | jq -r '.name as $name | .data.answers[]? | select(.type=="AAAA") | "\(.answer), \($name)"' > $OUTPUTFOLDER/satellite-ip-dom-pair-$DATESTR-AAAA.dat
