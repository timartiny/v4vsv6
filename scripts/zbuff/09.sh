#! /usr/bin/env bash

. ./variables.sh
echo "Running Day 2 v4 resolvers A Scan"
date
time -p cat ${OUTPUTFOLDER}/v4_cartesian_file_day2 | /home/timartiny/zdns/zdns/zdns A --local-addr "192.12.240.41" --output-file ${OUTPUTFOLDER}/v4_cartesian_A_lookups_${DATESTR}_day2.json
echo "Running Day 2 v4 resolvers AAAA Scan"
date
time -p cat ${OUTPUTFOLDER}/v4_cartesian_file_day2 | /home/timartiny/zdns/zdns/zdns AAAA --local-addr "192.12.240.41" --output-file ${OUTPUTFOLDER}/v4_cartesian_AAAA_lookups_${DATESTR}_day2.json
echo "Running Day 2 v6 resolvers A Scan"
date
time -p cat ${OUTPUTFOLDER}/v6_cartesian_file_day2 | /home/timartiny/zdns/zdns/zdns A --local-addr "2620:18f:30:4100::2" --output-file ${OUTPUTFOLDER}/v6_cartesian_A_lookups_${DATESTR}_day2.json
echo "Running Day 2 v6 resolvers AAAA Scan"
date
time -p cat ${OUTPUTFOLDER}/v6_cartesian_file_day2 | /home/timartiny/zdns/zdns/zdns AAAA --local-addr "2620:18f:30:4100::2" --output-file ${OUTPUTFOLDER}/v6_cartesian_AAAA_lookups_${DATESTR}_day2.json
date

echo "Setting up Day 2 Zgrab2 scan"
cat ${OUTPUTFOLDER}/v4_cartesian_A_lookups_${DATESTR}_day2.json | jq -r '.name as $name | .data.answers[]? | select(.type=="A") | "\(.answer), \($name)"' > ${OUTPUTFOLDER}/tmp
cat ${OUTPUTFOLDER}/v4_cartesian_AAAA_lookups_${DATESTR}_day2.json | jq -r '.name as $name | .data.answers[]? | select(.type=="A") | "\(.answer), \($name)"' >> ${OUTPUTFOLDER}/tmp
sort -u ${OUTPUTFOLDER}/tmp > ${OUTPUTFOLDER}/v4_A_ip_domain_list_day2.dat

# Now the AAAA record version
cat ${OUTPUTFOLDER}/v4_cartesian_AAAA_lookups_${DATESTR}_day2.json | jq -r '.name as $name | .data.answers[]? | select(.type=="AAAA") | "\(.answer), \($name)"' > ${OUTPUTFOLDER}/tmp
cat ${OUTPUTFOLDER}/v4_cartesian_A_lookups_${DATESTR}_day2.json | jq -r '.name as $name | .data.answers[]? | select(.type=="AAAA") | "\(.answer), \($name)"' >> ${OUTPUTFOLDER}/tmp
sort -u ${OUTPUTFOLDER}/tmp > ${OUTPUTFOLDER}/v4_AAAA_ip_domain_list_day2.dat

# Now the v6 version
cat ${OUTPUTFOLDER}/v6_cartesian_A_lookups_${DATESTR}_day2.json | jq -r '.name as $name | .data.answers[]? | select(.type=="A") | "\(.answer), \($name)"' > ${OUTPUTFOLDER}/tmp
cat ${OUTPUTFOLDER}/v6_cartesian_AAAA_lookups_${DATESTR}_day2.json | jq -r '.name as $name | .data.answers[]? | select(.type=="A") | "\(.answer), \($name)"' >> ${OUTPUTFOLDER}/tmp
sort -u ${OUTPUTFOLDER}/tmp > ${OUTPUTFOLDER}/v6_A_ip_domain_list_day2.dat
# Now the AAAA record version
cat ${OUTPUTFOLDER}/v6_cartesian_AAAA_lookups_${DATESTR}_day2.json | jq -r '.name as $name | .data.answers[]? | select(.type=="AAAA") | "\(.answer), \($name)"' > ${OUTPUTFOLDER}/tmp
cat ${OUTPUTFOLDER}/v6_cartesian_A_lookups_${DATESTR}_day2.json | jq -r '.name as $name | .data.answers[]? | select(.type=="AAAA") | "\(.answer), \($name)"' >> ${OUTPUTFOLDER}/tmp
sort -u ${OUTPUTFOLDER}/tmp > ${OUTPUTFOLDER}/v6_AAAA_ip_domain_list_day2.dat

# Now combine files into ip, domain lists:
cat ${OUTPUTFOLDER}/v4_A_ip_domain_list_day2.dat ${OUTPUTFOLDER}/v6_A_ip_domain_list_day2.dat > ${OUTPUTFOLDER}/tmp
sort -u ${OUTPUTFOLDER}/tmp > ${OUTPUTFOLDER}/A_ip_domain_list_${DATESTR}_day2.dat
# v6 version
cat ${OUTPUTFOLDER}/v4_AAAA_ip_domain_list_day2.dat ${OUTPUTFOLDER}/v6_AAAA_ip_domain_list_day2.dat > ${OUTPUTFOLDER}/tmp
sort -u ${OUTPUTFOLDER}/tmp > ${OUTPUTFOLDER}/AAAA_ip_domain_list_${DATESTR}_day2.dat

echo "Running Day 2 TLS banner grab on A records"
date
time -p cat ${OUTPUTFOLDER}/A_ip_domain_list_${DATESTR}_day2.dat | /home/timartiny/zgrab2/zgrab2 --source-ip=192.12.240.41 --output-file ${OUTPUTFOLDER}/A_tls_lookups_${DATESTR}_day2.json --connections-per-host 3 tls
echo "Running Day 2 TLS banner grab on AAAA records"
date
time -p cat ${OUTPUTFOLDER}/AAAA_ip_domain_list_${DATESTR}_day2.dat | /home/timartiny/zgrab2/zgrab2 --source-ip="2620:18f:30:4100::2" --output-file ${OUTPUTFOLDER}/AAAA_tls_lookups_${DATESTR}_day2.json --connections-per-host 3 tls 
date

echo "Getting Day 2 Error Data"
/home/timartiny/v4vsv6/error_test.py ${OUTPUTFOLDER}/A_tls_lookups_${DATESTR}_day2.json /data/timartiny/v4vsv6/GeoLite2-ASN.mmdb ${OUTPUTFOLDER}/${DATESTR}_A_asn_data_day2 3 ${OUTPUTFOLDER}/A-retry-list_day2 > ${OUTPUTFOLDER}/A-error-output_day2
/home/timartiny/v4vsv6/error_test.py ${OUTPUTFOLDER}/AAAA_tls_lookups_${DATESTR}_day2.json /data/timartiny/v4vsv6/GeoLite2-ASN.mmdb ${OUTPUTFOLDER}/${DATESTR}_AAAA_asn_data_day2 3 ${OUTPUTFOLDER}/AAAA-retry-list_day2 > ${OUTPUTFOLDER}/AAAA-error-output_day2
echo "Sorting Day 2 ASN Data"
cat ${OUTPUTFOLDER}/${DATESTR}_A_asn_data_day2 | grep -v "unknown_asn" | awk -F":" '{print $2", " $0}' | sort -k 1nr | sed 's/^.*, //' > ${OUTPUTFOLDER}/${DATESTR}_A_asn_data_sorted_day2
cat ${OUTPUTFOLDER}/${DATESTR}_AAAA_asn_data_day2 | grep -v "unknown_asn" | awk -F":" '{print $2", " $0}' | sort -k 1nr | sed 's/^.*, //' > ${OUTPUTFOLDER}/${DATESTR}_AAAA_asn_data_sorted_day2
date
echo "Copy ${OUTPUTFOLDER}/A-retry-list_day2 and ${OUTPUTFOLDER}/AAAA-retry-list_day2 to separate box to perform secondary Day 2 Scans"
echo "Make sure to run secondary scan and retrieve the A[AAA]_retry_lookups_${DATESTR}_day2.json files before running 10.sh"

