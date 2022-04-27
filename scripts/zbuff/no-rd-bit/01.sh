#! /usr/bin/env bash

. ../variables.sh

date
echo "Running nord bit scan on v4 resolvers"
/home/timartiny/v4vsv6/cmd/no-rd-bit/no-rd-bit --input ${OUTPUTFOLDER}/v4_cartesian_file --source-ip "192.12.240.41" --output ${OUTPUTFOLDER}/no-rd-bit/${DATESTR}-no-rd-bit-v4-responses.json
date

echo "Running nord bit scan on v6 resolvers"
/home/timartiny/v4vsv6/cmd/no-rd-bit/no-rd-bit --input ${OUTPUTFOLDER}/v6_cartesian_file --source-ip "2620:18f:30:4100::2" --output ${OUTPUTFOLDER}/no-rd-bit/${DATESTR}-no-rd-bit-v6-responses.json
date
