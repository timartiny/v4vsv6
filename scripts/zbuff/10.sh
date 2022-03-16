#! /usr/bin/env bash

. ./variables.sh
echo "Make sure you've copied over A_retry_lookups_${DATESTR}_day2.json and AAAA_retry_lookups_${DATESTR}_day2.json before running this script"
echo "Parsing Day 2 scans"
date
time -p /home/timartiny/v4vsv6/cmd/parseScans/parseScans --day 2 --data-folder ${OUTPUTFOLDER} --repeats --date-string ${DATESTR}
date

echo "Setting up Day 3 Scans"
jq -cr 'select(.censored_query == true) | select(.resolver_ip | contains (".")) | "\(.domain),\(.resolver_ip)"' ${OUTPUTFOLDER}/${DATESTR}-domain-resolver-results_day2.json > ${OUTPUTFOLDER}/v4_cartesian_file_day3
jq -cr 'select(.censored_query == true) | select(.resolver_ip | contains (":")) | "\(.domain),[\(.resolver_ip)]"' ${OUTPUTFOLDER}/${DATESTR}-domain-resolver-results_day2.json > ${OUTPUTFOLDER}/v6_cartesian_file_day3
date
echo "Done with Day 2 run 11.sh tomorrow!"

