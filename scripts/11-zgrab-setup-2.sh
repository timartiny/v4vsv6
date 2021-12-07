#! /usr/bin/env bash

. ./variables.sh

cat $OUTPUTFOLDER/v4_cartesian_A_lookups_$DATESTR.json | jq -r '.name as $name | .data.answers[]? | select(.type=="A") | "\(.answer), \($name)"' > $OUTPUTFOLDER/tmp
sort -u $OUTPUTFOLDER/tmp > $OUTPUTFOLDER/v4_A_ip_domain_list.dat

# Now the AAAA record version
cat $OUTPUTFOLDER/v4_cartesian_AAAA_lookups_$DATESTR.json | jq -r '.name as $name | .data.answers[]? | select(.type=="AAAA") | "\(.answer), \($name)"' > $OUTPUTFOLDER/tmp
sort -u $OUTPUTFOLDER/tmp > $OUTPUTFOLDER/v4_AAAA_ip_domain_list.dat

# Now the v6 version
cat $OUTPUTFOLDER/v6_cartesian_A_lookups_$DATESTR.json | jq -r '.name as $name | .data.answers[]? | select(.type=="A") | "\(.answer), \($name)"' > $OUTPUTFOLDER/tmp
sort -u $OUTPUTFOLDER/tmp > $OUTPUTFOLDER/v6_A_ip_domain_list.dat
# Now the AAAA record version
cat $OUTPUTFOLDER/v6_cartesian_AAAA_lookups_$DATESTR.json | jq -r '.name as $name | .data.answers[]? | select(.type=="AAAA") | "\(.answer), \($name)"' > $OUTPUTFOLDER/tmp
sort -u $OUTPUTFOLDER/tmp > $OUTPUTFOLDER/v6_AAAA_ip_domain_list.dat

# Now combine files into ip, domain lists:
cat $OUTPUTFOLDER/v4_A_ip_domain_list.dat $OUTPUTFOLDER/v6_A_ip_domain_list.dat > $OUTPUTFOLDER/tmp
sort -u $OUTPUTFOLDER/tmp > $OUTPUTFOLDER/A_ip_domain_list_$DATESTR.dat
# v6 version
cat $OUTPUTFOLDER/v4_AAAA_ip_domain_list.dat $OUTPUTFOLDER/v6_AAAA_ip_domain_list.dat > $OUTPUTFOLDER/tmp
sort -u $OUTPUTFOLDER/tmp > $OUTPUTFOLDER/AAAA_ip_domain_list_$DATESTR.dat

