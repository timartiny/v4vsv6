#! /usr/bin/env bash

. ./variables.sh

echo "Make sure you've copied over A_retry_lookups_${DATESTR}_day1.json and AAAA_retry_lookups_${DATESTR}_day1.json before running this script"
echo "Parsing Day 1 scans"
date
time -p /home/timartiny/v4vsv6/cmd/parseScans/parseScans --day 1 --data-folder ${OUTPUTFOLDER} --repeats --date-string ${DATESTR}
date

echo "Setting up Day 2 Scans"
jq -cr 'select(.censored_query == true) | select(.resolver_ip | contains (".")) | "\(.domain),\(.resolver_ip)"' ${OUTPUTFOLDER}/${DATESTR}-domain-resolver-results_day1.json > ${OUTPUTFOLDER}/v4_cartesian_file_day2
jq -cr 'select(.censored_query == true) | select(.resolver_ip | contains (":")) | "\(.domain),[\(.resolver_ip)]"' ${OUTPUTFOLDER}/${DATESTR}-domain-resolver-results_day1.json > ${OUTPUTFOLDER}/v6_cartesian_file_day2
date
echo "Done with Day 1 run 09.sh tomorrow!"

