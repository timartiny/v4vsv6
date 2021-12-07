#! /usr/bin/env bash
. ./variables.sh
#cat satellite-domains.json | jq '.[]' -r | /home/timartiny/zdns/zdns/zdns A --name-servers=8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1 --output-file $OUTPUTFOLDER/satellite-A-$DATESTR.json
#cat satellite-domains.json | jq '.[]' -r | /home/timartiny/zdns/zdns/zdns AAAA --name-servers=8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1 --output-file $OUTPUTFOLDER/satellite-AAAA-$DATESTR.json
cat satellite-domains-head.json | jq '.[]' -r | /home/timartiny/zdns/zdns/zdns A --name-servers=8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1 --output-file $OUTPUTFOLDER/satellite-A-$DATESTR.json
cat satellite-domains-head.json | jq '.[]' -r | /home/timartiny/zdns/zdns/zdns AAAA --name-servers=8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1 --output-file $OUTPUTFOLDER/satellite-AAAA-$DATESTR.json
