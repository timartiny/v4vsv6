#! /usr/bin/env bash

. ./variables.sh

echo "Running v4 resolvers A Scan"
date
time -p cat $OUTPUTFOLDER/v4_cartesian_file | /home/timartiny/zdns/zdns/zdns A --output-file $OUTPUTFOLDER/v4_cartesian_A_lookups_$DATESTR.json
echo "Running v4 resolvers AAAA Scan"
date
time -p cat $OUTPUTFOLDER/v4_cartesian_file | /home/timartiny/zdns/zdns/zdns AAAA --output-file $OUTPUTFOLDER/v4_cartesian_AAAA_lookups_$DATESTR.json
echo "Running v6 resolvers A Scan"
date
time -p cat $OUTPUTFOLDER/v6_cartesian_file | /home/timartiny/zdns/zdns/zdns A --local-addr "2620:18f:30:4100::2" --output-file $OUTPUTFOLDER/v6_cartesian_A_lookups_$DATESTR.json
echo "Running v6 resolvers AAAA Scan"
date
time -p cat $OUTPUTFOLDER/v6_cartesian_file | /home/timartiny/zdns/zdns/zdns AAAA --local-addr "2620:18f:30:4100::2" --output-file $OUTPUTFOLDER/v6_cartesian_AAAA_lookups_$DATESTR.json
