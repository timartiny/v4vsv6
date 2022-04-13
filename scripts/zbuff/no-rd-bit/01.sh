#! /usr/bin/env bash

. ../variables.sh

date
echo "Making v4 and v6 Resolver files"
awk '{print $1}' ${OUTPUTFOLDER}/${DATESTR}-single-resolvers-country-correct-sorted > ${OUTPUTFOLDER}/no-rd-bit/v6-resolvers
awk '{print $2}' ${OUTPUTFOLDER}/${DATESTR}-single-resolvers-country-correct-sorted > ${OUTPUTFOLDER}/no-rd-bit/v4-resolvers
date

echo "Making domain list file"
jq -rc '.domain' ${OUTPUTFOLDER}/full-details-v4-and-v6-and-tls-${DATESTR}.json > ${OUTPUTFOLDER}/no-rd-bit/domains
date

echo "Running nord bit scan on v4 resolvers"
/home/timartiny/v4vsv6/cmd/no-rd-bit/no-rd-bit --resolvers ${OUTPUTFOLDER}/no-rd-bit/v4-resolvers --domains ${OUTPUTFOLDER}/no-rd-bit/domains --source-ip "192.12.240.41" --output ${OUTPUTFOLDER}/no-rd-bit/${DATESTR}-no-rd-bit-v4-responses.json
date

echo "Running nord bit scan on v6 resolvers"
/home/timartiny/v4vsv6/cmd/no-rd-bit/no-rd-bit --resolvers ${OUTPUTFOLDER}/no-rd-bit/v6-resolvers --domains ${OUTPUTFOLDER}/no-rd-bit/domains --source-ip "2620:18f:30:4100::2" --output ${OUTPUTFOLDER}/no-rd-bit/${DATESTR}-no-rd-bit-v6-responses.json
date
