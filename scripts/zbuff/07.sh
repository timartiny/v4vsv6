#! /usr/bin/env bash

. ./variables.sh

echo "Performing DNS A/AAAA look ups on Satellite domains from Google and Cloudflare's DNS servers"
time -p cat satellite-domains.json | jq '.[]' -r | /home/timartiny/zdns/zdns/zdns A --local-addr "192.12.240.41" --name-servers=8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1 --output-file ${OUTPUTFOLDER}/satellite-A-${DATESTR}.json
time -p cat satellite-domains.json | jq '.[]' -r | /home/timartiny/zdns/zdns/zdns AAAA --local-addr "192.12.240.41" --name-servers=8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1 --output-file ${OUTPUTFOLDER}/satellite-AAAA-${DATESTR}.json
date

echo "Performing DNS NS look ups on Satellite domains from Google and Cloudflare's DNS Servers"
time -p cat satellite-domains.json | jq '.[]' -r | /home/timartiny/zdns/zdns/zdns NS --local-addr "192.12.240.41" --name-servers=8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1 --output-file ${OUTPUTFOLDER}/satellite-NS-${DATESTR}.json
date

echo "Performing DNS A/AAAA look ups on Satellite domains from Google and Cloudflare's DNS servers"
time -p cat satellite-domains.json | jq '.[]' -r | /home/timartiny/zdns/zdns/zdns A --local-addr "192.12.240.41" --name-servers=8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1 --output-file ${OUTPUTFOLDER}/satellite-A-${DATESTR}.json
date

echo "Performing DNS A/AAAA look ups on Satellite domain Name servers"
time -p jq '.data.answers[]? | select(.type == "NS") | .answer' -r ${OUTPUTFOLDER}/satellite-NS-${DATESTR}.json | /home/timartiny/zdns/zdns/zdns A --local-addr "192.12.240.41" --name-servers=8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1 --output-file ${OUTPUTFOLDER}/satellite-NS-A-${DATESTR}.json
time -p jq '.data.answers[]? | select(.type == "NS") | .answer' -r ${OUTPUTFOLDER}/satellite-NS-${DATESTR}.json | /home/timartiny/zdns/zdns/zdns AAAA --local-addr "192.12.240.41" --name-servers=8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1 --output-file ${OUTPUTFOLDER}/satellite-NS-AAAA-${DATESTR}.json
date

echo "Setting up Zgrab2 scan for Satellite Domains to determine which have TLS certificates"
cat ${OUTPUTFOLDER}/satellite-A-${DATESTR}.json | jq -r '.name as $name | .data.answers[]? | select(.type=="A") | "\(.answer), \($name)"' > ${OUTPUTFOLDER}/satellite-ip-dom-pair-${DATESTR}-A.dat
cat ${OUTPUTFOLDER}/satellite-AAAA-${DATESTR}.json | jq -r '.name as $name | .data.answers[]? | select(.type=="AAAA") | "\(.answer), \($name)"' > ${OUTPUTFOLDER}/satellite-ip-dom-pair-${DATESTR}-AAAA.dat
date

echo "Starting Zgrab2 scan"
time -p cat ${OUTPUTFOLDER}/satellite-ip-dom-pair-${DATESTR}-A.dat | /home/timartiny/zgrab2/zgrab2 --source-ip=192.12.240.41 -o ${OUTPUTFOLDER}/satellite-zgrab-A-${DATESTR}.json tls
time -p cat ${OUTPUTFOLDER}/satellite-ip-dom-pair-${DATESTR}-AAAA.dat | /home/timartiny/zgrab2/zgrab2 --source-ip="2620:18f:30:4100::2" -o ${OUTPUTFOLDER}/satellite-zgrab-AAAA-${DATESTR}.json tls
date

echo "Parsing DNS and Zgrab2 scan data"
echo "Determining which domains meet our technical requirements"
/home/timartiny/v4vsv6/cmd/querylist/querylist --v4_dns ${OUTPUTFOLDER}/satellite-A-${DATESTR}.json --v6_dns ${OUTPUTFOLDER}/satellite-AAAA-${DATESTR}.json  --v4_tls ${OUTPUTFOLDER}/satellite-zgrab-A-${DATESTR}.json --v6_tls ${OUTPUTFOLDER}/satellite-zgrab-AAAA-${DATESTR}.json --ns ${OUTPUTFOLDER}/satellite-NS-${DATESTR}.json --ns_a ${OUTPUTFOLDER}/satellite-NS-A-${DATESTR}.json --ns_aaaa ${OUTPUTFOLDER}/satellite-NS-AAAA-${DATESTR}.json --citizen_lab_directory /home/timartiny/test-lists/lists/ --out_file ${OUTPUTFOLDER}/satellite-full-details-${DATESTR}.json

cat ${OUTPUTFOLDER}/satellite-full-details-${DATESTR}.json | jq "select(.has_v4==true and .has_v6==true)" -c > ${OUTPUTFOLDER}/full-details-v4-and-v6-${DATESTR}.json
cat ${OUTPUTFOLDER}/full-details-v4-and-v6-${DATESTR}.json | jq "select(.has_v4_tls==true and .has_v6_tls==true)" -c > ${OUTPUTFOLDER}/full-details-v4-and-v6-and-tls-${DATESTR}.json
echo "Adding control domains"
echo '{"domain":"v4vsv6.com","has_v4":true,"has_v6":true,"has_v4_tls":true,"has_v6_tls":true,"citizen_lab_global_list":false,"citizen_lab_country_list":null}' >> ${OUTPUTFOLDER}/full-details-v4-and-v6-and-tls-${DATESTR}.json
echo '{"domain":"test1.v4vsv6.com","has_v4":true,"has_v6":true,"has_v4_tls":true,"has_v6_tls":true,"citizen_lab_global_list":false,"citizen_lab_country_list":null}' >> ${OUTPUTFOLDER}/full-details-v4-and-v6-and-tls-${DATESTR}.json
echo '{"domain":"test2.v4vsv6.com","has_v4":true,"has_v6":true,"has_v4_tls":true,"has_v6_tls":true,"citizen_lab_global_list":false,"citizen_lab_country_list":null}' >> ${OUTPUTFOLDER}/full-details-v4-and-v6-and-tls-${DATESTR}.json
/home/timartiny/v4vsv6/domain_resolver_pairs.py ${OUTPUTFOLDER}/full-details-v4-and-v6-and-tls-${DATESTR}.json ${DATESTR}-single-resolvers-country-correct-sorted ${OUTPUTFOLDER}/v4_cartesian_file ${OUTPUTFOLDER}/v6_cartesian_file

echo "Running v4 resolvers A Scan"
date
time -p cat ${OUTPUTFOLDER}/v4_cartesian_file | /home/timartiny/zdns/zdns/zdns A --local-addr "192.12.240.41" --output-file ${OUTPUTFOLDER}/v4_cartesian_A_lookups_${DATESTR}_day1.json
echo "Running v4 resolvers AAAA Scan"
date
time -p cat ${OUTPUTFOLDER}/v4_cartesian_file | /home/timartiny/zdns/zdns/zdns AAAA --local-addr "192.12.240.41" --output-file ${OUTPUTFOLDER}/v4_cartesian_AAAA_lookups_${DATESTR}_day1.json
echo "Running v6 resolvers A Scan"
date
time -p cat ${OUTPUTFOLDER}/v6_cartesian_file | /home/timartiny/zdns/zdns/zdns A --local-addr "2620:18f:30:4100::2" --output-file ${OUTPUTFOLDER}/v6_cartesian_A_lookups_${DATESTR}_day1.json
echo "Running v6 resolvers AAAA Scan"
date
time -p cat ${OUTPUTFOLDER}/v6_cartesian_file | /home/timartiny/zdns/zdns/zdns AAAA --local-addr "2620:18f:30:4100::2" --output-file ${OUTPUTFOLDER}/v6_cartesian_AAAA_lookups_${DATESTR}_day1.json
date

echo "Setting Day 1 Zgrab2 scan"
cat ${OUTPUTFOLDER}/v4_cartesian_A_lookups_${DATESTR}_day1.json | jq -r '.name as $name | .data.answers[]? | select(.type=="A") | "\(.answer), \($name)"' > ${OUTPUTFOLDER}/tmp
cat ${OUTPUTFOLDER}/v4_cartesian_AAAA_lookups_${DATESTR}_day1.json | jq -r '.name as $name | .data.answers[]? | select(.type=="A") | "\(.answer), \($name)"' >> ${OUTPUTFOLDER}/tmp
sort -u ${OUTPUTFOLDER}/tmp > ${OUTPUTFOLDER}/v4_A_ip_domain_list_day1.dat

# Now the AAAA record version
cat ${OUTPUTFOLDER}/v4_cartesian_AAAA_lookups_${DATESTR}_day1.json | jq -r '.name as $name | .data.answers[]? | select(.type=="AAAA") | "\(.answer), \($name)"' > ${OUTPUTFOLDER}/tmp
cat ${OUTPUTFOLDER}/v4_cartesian_A_lookups_${DATESTR}_day1.json | jq -r '.name as $name | .data.answers[]? | select(.type=="AAAA") | "\(.answer), \($name)"' >> ${OUTPUTFOLDER}/tmp
sort -u ${OUTPUTFOLDER}/tmp > ${OUTPUTFOLDER}/v4_AAAA_ip_domain_list_day1.dat

# Now the v6 version
cat ${OUTPUTFOLDER}/v6_cartesian_A_lookups_${DATESTR}_day1.json | jq -r '.name as $name | .data.answers[]? | select(.type=="A") | "\(.answer), \($name)"' > ${OUTPUTFOLDER}/tmp
cat ${OUTPUTFOLDER}/v6_cartesian_AAAA_lookups_${DATESTR}_day1.json | jq -r '.name as $name | .data.answers[]? | select(.type=="A") | "\(.answer), \($name)"' >> ${OUTPUTFOLDER}/tmp
sort -u ${OUTPUTFOLDER}/tmp > ${OUTPUTFOLDER}/v6_A_ip_domain_list_day1.dat
# Now the AAAA record version
cat ${OUTPUTFOLDER}/v6_cartesian_AAAA_lookups_${DATESTR}_day1.json | jq -r '.name as $name | .data.answers[]? | select(.type=="AAAA") | "\(.answer), \($name)"' > ${OUTPUTFOLDER}/tmp
cat ${OUTPUTFOLDER}/v6_cartesian_A_lookups_${DATESTR}_day1.json | jq -r '.name as $name | .data.answers[]? | select(.type=="AAAA") | "\(.answer), \($name)"' >> ${OUTPUTFOLDER}/tmp
sort -u ${OUTPUTFOLDER}/tmp > ${OUTPUTFOLDER}/v6_AAAA_ip_domain_list_day1.dat

# Now combine files into ip, domain lists:
cat ${OUTPUTFOLDER}/v4_A_ip_domain_list_day1.dat ${OUTPUTFOLDER}/v6_A_ip_domain_list_day1.dat > ${OUTPUTFOLDER}/tmp
sort -u ${OUTPUTFOLDER}/tmp > ${OUTPUTFOLDER}/A_ip_domain_list_${DATESTR}_day1.dat
# v6 version
cat ${OUTPUTFOLDER}/v4_AAAA_ip_domain_list_day1.dat ${OUTPUTFOLDER}/v6_AAAA_ip_domain_list_day1.dat > ${OUTPUTFOLDER}/tmp
sort -u ${OUTPUTFOLDER}/tmp > ${OUTPUTFOLDER}/AAAA_ip_domain_list_${DATESTR}_day1.dat

echo "Running TLS banner grab on A records"
date
time -p cat ${OUTPUTFOLDER}/A_ip_domain_list_${DATESTR}_day1.dat | /home/timartiny/zgrab2/zgrab2 --source-ip=192.12.240.41 --output-file ${OUTPUTFOLDER}/A_tls_lookups_${DATESTR}_day1.json --connections-per-host 3 tls
echo "Running TLS banner grab on AAAA records"
date
time -p cat ${OUTPUTFOLDER}/AAAA_ip_domain_list_${DATESTR}_day1.dat | /home/timartiny/zgrab2/zgrab2 --source-ip="2620:18f:30:4100::2" --output-file ${OUTPUTFOLDER}/AAAA_tls_lookups_${DATESTR}_day1.json --connections-per-host 3 tls 
date

echo "Getting Error Data"
/home/timartiny/v4vsv6/error_test.py ${OUTPUTFOLDER}/A_tls_lookups_${DATESTR}_day1.json /data/timartiny/v4vsv6/GeoLite2-ASN.mmdb ${OUTPUTFOLDER}/${DATESTR}_A_asn_data_day1 3 ${OUTPUTFOLDER}/A-retry-list_day1 > ${OUTPUTFOLDER}/A-error-output_day1
/home/timartiny/v4vsv6/error_test.py ${OUTPUTFOLDER}/AAAA_tls_lookups_${DATESTR}_day1.json /data/timartiny/v4vsv6/GeoLite2-ASN.mmdb ${OUTPUTFOLDER}/${DATESTR}_AAAA_asn_data_day1 3 ${OUTPUTFOLDER}/AAAA-retry-list_day1 > ${OUTPUTFOLDER}/AAAA-error-output_day1
echo "Sorting ASN Data"
cat ${OUTPUTFOLDER}/${DATESTR}_A_asn_data_day1 | grep -v "unknown_asn" | awk -F":" '{print $2", " $0}' | sort -k 1nr | sed 's/^.*, //' > ${OUTPUTFOLDER}/${DATESTR}_A_asn_data_sorted_day1
cat ${OUTPUTFOLDER}/${DATESTR}_AAAA_asn_data_day1 | grep -v "unknown_asn" | awk -F":" '{print $2", " $0}' | sort -k 1nr | sed 's/^.*, //' > ${OUTPUTFOLDER}/${DATESTR}_AAAA_asn_data_sorted_day1
date
echo "Copy ${OUTPUTFOLDER}/A-retry-list_day1 and ${OUTPUTFOLDER}/AAAA-retry-list_day1 to separate box to perform secondary Day 1 Scans"
echo "Make sure to run secondary scan and retrieve the A[AAA]_retry_lookups_${DATESTR}_day1.json files before running 08.sh"

