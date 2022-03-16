#! /usr/bin/env bash

. ./variables.sh

echo "Running Day 3 v4 resolvers A Scan"
date
time -p cat ${OUTPUTFOLDER}/v4_cartesian_file_day3 | /home/timartiny/zdns/zdns/zdns A --local-addr "<local-v4-address-to-scan-from>" --output-file ${OUTPUTFOLDER}/v4_cartesian_A_lookups_${DATESTR}_day3.json
echo "Running Day 3 v4 resolvers AAAA Scan"
date
time -p cat ${OUTPUTFOLDER}/v4_cartesian_file_day3 | /home/timartiny/zdns/zdns/zdns AAAA --local-addr "<local-v4-address-to-scan-from>" --output-file ${OUTPUTFOLDER}/v4_cartesian_AAAA_lookups_${DATESTR}_day3.json
echo "Running Day 3 v6 resolvers A Scan"
date
time -p cat ${OUTPUTFOLDER}/v6_cartesian_file_day3 | /home/timartiny/zdns/zdns/zdns A --local-addr "<local-v6-address-to-scan-from>" --output-file ${OUTPUTFOLDER}/v6_cartesian_A_lookups_${DATESTR}_day3.json
echo "Running Day 3 v6 resolvers AAAA Scan"
date
time -p cat ${OUTPUTFOLDER}/v6_cartesian_file_day3 | /home/timartiny/zdns/zdns/zdns AAAA --local-addr "<local-v6-address-to-scan-from>" --output-file ${OUTPUTFOLDER}/v6_cartesian_AAAA_lookups_${DATESTR}_day3.json
date

echo "Setting up Day 3 Zgrab2 scan"
cat ${OUTPUTFOLDER}/v4_cartesian_A_lookups_${DATESTR}_day3.json | jq -r '.name as $name | .data.answers[]? | select(.type=="A") | "\(.answer), \($name)"' > ${OUTPUTFOLDER}/tmp
cat ${OUTPUTFOLDER}/v4_cartesian_AAAA_lookups_${DATESTR}_day3.json | jq -r '.name as $name | .data.answers[]? | select(.type=="A") | "\(.answer), \($name)"' >> ${OUTPUTFOLDER}/tmp
sort -u ${OUTPUTFOLDER}/tmp > ${OUTPUTFOLDER}/v4_A_ip_domain_list_day3.dat

# Now the AAAA record version
cat ${OUTPUTFOLDER}/v4_cartesian_AAAA_lookups_${DATESTR}_day3.json | jq -r '.name as $name | .data.answers[]? | select(.type=="AAAA") | "\(.answer), \($name)"' > ${OUTPUTFOLDER}/tmp
cat ${OUTPUTFOLDER}/v4_cartesian_A_lookups_${DATESTR}_day3.json | jq -r '.name as $name | .data.answers[]? | select(.type=="AAAA") | "\(.answer), \($name)"' >> ${OUTPUTFOLDER}/tmp
sort -u ${OUTPUTFOLDER}/tmp > ${OUTPUTFOLDER}/v4_AAAA_ip_domain_list_day3.dat

# Now the v6 version
cat ${OUTPUTFOLDER}/v6_cartesian_A_lookups_${DATESTR}_day3.json | jq -r '.name as $name | .data.answers[]? | select(.type=="A") | "\(.answer), \($name)"' > ${OUTPUTFOLDER}/tmp
cat ${OUTPUTFOLDER}/v6_cartesian_AAAA_lookups_${DATESTR}_day3.json | jq -r '.name as $name | .data.answers[]? | select(.type=="A") | "\(.answer), \($name)"' >> ${OUTPUTFOLDER}/tmp
sort -u ${OUTPUTFOLDER}/tmp > ${OUTPUTFOLDER}/v6_A_ip_domain_list_day3.dat
# Now the AAAA record version
cat ${OUTPUTFOLDER}/v6_cartesian_AAAA_lookups_${DATESTR}_day3.json | jq -r '.name as $name | .data.answers[]? | select(.type=="AAAA") | "\(.answer), \($name)"' > ${OUTPUTFOLDER}/tmp
cat ${OUTPUTFOLDER}/v6_cartesian_A_lookups_${DATESTR}_day3.json | jq -r '.name as $name | .data.answers[]? | select(.type=="AAAA") | "\(.answer), \($name)"' >> ${OUTPUTFOLDER}/tmp
sort -u ${OUTPUTFOLDER}/tmp > ${OUTPUTFOLDER}/v6_AAAA_ip_domain_list_day3.dat

# Now combine files into ip, domain lists:
cat ${OUTPUTFOLDER}/v4_A_ip_domain_list_day3.dat ${OUTPUTFOLDER}/v6_A_ip_domain_list_day3.dat > ${OUTPUTFOLDER}/tmp
sort -u ${OUTPUTFOLDER}/tmp > ${OUTPUTFOLDER}/A_ip_domain_list_${DATESTR}_day3.dat
# v6 version
cat ${OUTPUTFOLDER}/v4_AAAA_ip_domain_list_day3.dat ${OUTPUTFOLDER}/v6_AAAA_ip_domain_list_day3.dat > ${OUTPUTFOLDER}/tmp
sort -u ${OUTPUTFOLDER}/tmp > ${OUTPUTFOLDER}/AAAA_ip_domain_list_${DATESTR}_day3.dat

echo "Running Day 3 TLS banner grab on A records"
date
time -p cat ${OUTPUTFOLDER}/A_ip_domain_list_${DATESTR}_day3.dat | /home/timartiny/zgrab2/zgrab2 --source-ip=<local-v4-address-to-scan-from> --output-file ${OUTPUTFOLDER}/A_tls_lookups_${DATESTR}_day3.json --connections-per-host 3 tls
echo "Running Day 3 TLS banner grab on AAAA records"
date
time -p cat ${OUTPUTFOLDER}/AAAA_ip_domain_list_${DATESTR}_day3.dat | /home/timartiny/zgrab2/zgrab2 --source-ip="<local-v6-address-to-scan-from>" --output-file ${OUTPUTFOLDER}/AAAA_tls_lookups_${DATESTR}_day3.json --connections-per-host 3 tls 
date

echo "Getting Day 3 Error Data"
/home/timartiny/v4vsv6/error_test.py ${OUTPUTFOLDER}/A_tls_lookups_${DATESTR}_day3.json /data/timartiny/v4vsv6/GeoLite2-ASN.mmdb ${OUTPUTFOLDER}/${DATESTR}_A_asn_data_day3 3 ${OUTPUTFOLDER}/A-retry-list_day3 > ${OUTPUTFOLDER}/A-error-output_day3
/home/timartiny/v4vsv6/error_test.py ${OUTPUTFOLDER}/AAAA_tls_lookups_${DATESTR}_day3.json /data/timartiny/v4vsv6/GeoLite2-ASN.mmdb ${OUTPUTFOLDER}/${DATESTR}_AAAA_asn_data_day3 3 ${OUTPUTFOLDER}/AAAA-retry-list_day3 > ${OUTPUTFOLDER}/AAAA-error-output_day3
echo "Sorting Day 3 ASN Data"
cat ${OUTPUTFOLDER}/${DATESTR}_A_asn_data_day3 | grep -v "unknown_asn" | awk -F":" '{print $2", " $0}' | sort -k 1nr | sed 's/^.*, //' > ${OUTPUTFOLDER}/${DATESTR}_A_asn_data_sorted_day3
cat ${OUTPUTFOLDER}/${DATESTR}_AAAA_asn_data_day3 | grep -v "unknown_asn" | awk -F":" '{print $2", " $0}' | sort -k 1nr | sed 's/^.*, //' > ${OUTPUTFOLDER}/${DATESTR}_AAAA_asn_data_sorted_day3
date
echo "Copy ${OUTPUTFOLDER}/A-retry-list_day3 and ${OUTPUTFOLDER}/AAAA-retry-list_day3 to separate box to perform secondary Day 3 Scans"
echo "Make sure to run secondary scan and retrieve the A[AAA]_retry_lookups_${DATESTR}_day3.json files before running 12.sh"

