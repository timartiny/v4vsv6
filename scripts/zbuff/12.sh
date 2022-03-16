#! /usr/bin/env bash

. ./variables.sh
echo "Make sure you've copied over A_retry_lookups_${DATESTR}_day3.json and AAAA_retry_lookups_${DATESTR}_day3.json before running this script"
echo "Parsing Day 3 scans"
date
time -p /home/timartiny/v4vsv6/cmd/parseScans/parseScans --day 3 --data-folder ${OUTPUTFOLDER} --repeats --date-string ${DATESTR}
date

echo "Merging the three days worth of results into one file"
time -p /home/timartiny/v4vsv6/cmd/mergeResults/mergeResults --data-folder ${OUTPUTFOLDER} --date-string ${DATESTR}
date

echo "Interpreting data to answer Questions"
time -p /home/timartiny/v4vsv6/cmd/interpretResults/interpretResults --data-folder ${OUTPUTFOLDER} --date-string ${DATESTR} --results-file ${OUTPUTFOLDER}/${DATESTR}-domain-resolver-results.json --resolver-file ${OUTPUTFOLDER}/${DATESTR}-single-resolvers-country-correct-sorted
date
echo "All Done!"

