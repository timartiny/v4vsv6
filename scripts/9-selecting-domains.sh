#! /usr/bin/env bash
. ./variables.sh
cat $OUTPUTFOLDER/satellite-full-details-$DATESTR.json | jq "select(.has_v4==true and .has_v6==true)" -c > $OUTPUTFOLDER/full-details-v4-and-v6-$DATESTR.json
cat $OUTPUTFOLDER/full-details-v4-and-v6-$DATESTR.json | jq "select(.has_v4_tls==true and .has_v6_tls==true)" -c > $OUTPUTFOLDER/full-details-v4-and-v6-and-tls-$DATESTR.json
echo '{"domain":"v4vsv6.com","has_v4":true,"has_v6":true,"has_v4_tls":true,"has_v6_tls":true,"citizen_lab_global_list":false,"citizen_lab_country_list":null}' >> $OUTPUTFOLDER/full-details-v4-and-v6-and-tls-$DATESTR.json
echo '{"domain":"test1.v4vsv6.com","has_v4":true,"has_v6":true,"has_v4_tls":true,"has_v6_tls":true,"citizen_lab_global_list":false,"citizen_lab_country_list":null}' >> $OUTPUTFOLDER/full-details-v4-and-v6-and-tls-$DATESTR.json
echo '{"domain":"test2.v4vsv6.com","has_v4":true,"has_v6":true,"has_v4_tls":true,"has_v6_tls":true,"citizen_lab_global_list":false,"citizen_lab_country_list":null}' >> $OUTPUTFOLDER/full-details-v4-and-v6-and-tls-$DATESTR.json
/home/timartiny/v4vsv6/domain_resolver_pairs.py $OUTPUTFOLDER/full-details-v4-and-v6-and-tls-$DATESTR.json $DATESTR-single-resolvers-country-correct-sorted $OUTPUTFOLDER/v4_cartesian_file $OUTPUTFOLDER/v6_cartesian_file
