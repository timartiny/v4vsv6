#! /usr/bin/env bash

. ./variables.sh

echo "Make sure to grab the ${DATESTR}-v4.pcap file from the v4 NS before running this."
echo "Matching v4 IPs to v6 IPs from PCAP"
date
tcpdump -n -r ${OUTPUTFOLDER}/${DATESTR}-v4.pcap | python3 /home/timartiny/v6censorship/probe-dns/data/match.py 4to6 > ${OUTPUTFOLDER}/${DATESTR}-v4-to-v6
echo "Removing duplicate IPs"
grep -v ',' ${OUTPUTFOLDER}/${DATESTR}-v4-to-v6 > ${OUTPUTFOLDER}/${DATESTR}-v4-to-v6-single-resolvers
echo "Applying Country codes to IPs"
python3 /home/timartiny/v6censorship/probe-dns/data/cc.py ${OUTPUTFOLDER}/${DATESTR}-v4-to-v6-single-resolvers > ${OUTPUTFOLDER}/${DATESTR}-v4-to-v6-single-resolvers-country-tmp
echo "Removing Non matching Country Codes"
grep -v '!!' ${OUTPUTFOLDER}/${DATESTR}-v4-to-v6-single-resolvers-country-tmp | grep -v 'None' | grep -v 'missing' > ${OUTPUTFOLDER}/${DATESTR}-v4-to-v6-single-resolvers-country
echo "Finding duplicate resolvers"
cat ${OUTPUTFOLDER}/${DATESTR}-v4-to-v6-single-resolvers-country | awk '{print $1}' | sort | uniq -d > ${OUTPUTFOLDER}/${DATESTR}-v4-to-v6-dup-v4
cat ${OUTPUTFOLDER}/${DATESTR}-v4-to-v6-single-resolvers-country | awk '{print $2}' | sort | uniq -d > ${OUTPUTFOLDER}/${DATESTR}-v4-to-v6-dup-v6
echo "Removing duplicate resolvers"
grep -vF -f ${OUTPUTFOLDER}/${DATESTR}-v4-to-v6-dup-v6 ${OUTPUTFOLDER}/${DATESTR}-v4-to-v6-single-resolvers-country > ${OUTPUTFOLDER}/${DATESTR}-v4-to-v6-single-resolvers-country-tmp
grep -vF -f ${OUTPUTFOLDER}/${DATESTR}-v4-to-v6-dup-v4 ${OUTPUTFOLDER}/${DATESTR}-v4-to-v6-single-resolvers-country-tmp > ${OUTPUTFOLDER}/${DATESTR}-v4-to-v6-single-resolvers-country
sort ${OUTPUTFOLDER}/${DATESTR}-v4-to-v6-single-resolvers-country > ${OUTPUTFOLDER}/${DATESTR}-v4-to-v6-single-resolvers-country-sorted
rm ${OUTPUTFOLDER}/${DATESTR}-v4-to-v6-single-resolvers-country-tmp

echo "Create a list of all resolver pairs"
cp ${OUTPUTFOLDER}/${DATESTR}-v6-to-v4-single-resolvers-country ${OUTPUTFOLDER}/${DATESTR}-single-resolvers-country-all
awk '{print $2, $1, $3}' ${OUTPUTFOLDER}/${DATESTR}-v4-to-v6-single-resolvers-country >> ${OUTPUTFOLDER}/${DATESTR}-single-resolvers-country-all
awk '{print $1}' ${OUTPUTFOLDER}/${DATESTR}-single-resolvers-country-all | sort | uniq -d > ${OUTPUTFOLDER}/${DATESTR}-dup-v6
awk '{print $2}' ${OUTPUTFOLDER}/${DATESTR}-single-resolvers-country-all | sort | uniq -d > ${OUTPUTFOLDER}/${DATESTR}-dup-v4
awk '{if ($3 != "") print $0}' ${OUTPUTFOLDER}/${DATESTR}-single-resolvers-country-all | sort > ${OUTPUTFOLDER}/${DATESTR}-single-resolvers-country-all-sorted
echo "Remove duplicate space"
sed 's/  / /g' ${OUTPUTFOLDER}/${DATESTR}-single-resolvers-country-all-sorted > tmp
mv tmp ${OUTPUTFOLDER}/${DATESTR}-single-resolvers-country-all-sorted
uniq -d ${OUTPUTFOLDER}/${DATESTR}-single-resolvers-country-all-sorted > ${OUTPUTFOLDER}/${DATESTR}-single-resolvers-country-sorted
date

echo "Starting Control Probes"
echo "Performing A Record Request for tlsfingerprint.io from v6 resolvers"
time -p cat ${OUTPUTFOLDER}/${DATESTR}-single-resolvers-country-sorted | awk '{print $1}' | /home/timartiny/v6censorship/probe-dns/probe -source-ip <local-v6-address-to-scan-from> -domain tlsfingerprint.io -record A -workers 1000 -prefix=false > ${OUTPUTFOLDER}/${DATESTR}-v6-resolve-v4.out
echo "Performing A Record Request for tlsfingerprint.io from v4 resolvers"
time -p cat ${OUTPUTFOLDER}/${DATESTR}-single-resolvers-country-sorted | awk '{print $2}' | /home/timartiny/v6censorship/probe-dns/probe -source-ip <local-v4-address-to-scan-from> -domain tlsfingerprint.io -record A -workers 1000 -prefix=false > ${OUTPUTFOLDER}/${DATESTR}-v4-resolve-v4.out
echo "Performing AAAA Record Request for v6ns.tlsfingerprint.io from v6 resolvers"
time -p cat ${OUTPUTFOLDER}/${DATESTR}-single-resolvers-country-sorted | awk '{print $1}' | /home/timartiny/v6censorship/probe-dns/probe -source-ip <local-v6-address-to-scan-from> -domain v6ns.tlsfingerprint.io -record AAAA -workers 1000 -prefix=false > ${OUTPUTFOLDER}/${DATESTR}-v6-resolve-v6.out
echo "Performing AAAA Record Request for v6ns.tlsfingerprint.io from v4 resolvers"
time -p cat ${OUTPUTFOLDER}/${DATESTR}-single-resolvers-country-sorted | awk '{print $2}' | /home/timartiny/v6censorship/probe-dns/probe -source-ip <local-v4-address-to-scan-from> -domain v6ns.tlsfingerprint.io -record AAAA -workers 1000 -prefix=false > ${OUTPUTFOLDER}/${DATESTR}-v4-resolve-v6.out
date

echo "Checking responses, ensuring resolvers passed control"
grep "Response" ${OUTPUTFOLDER}/${DATESTR}-v4-resolve-v4.out | grep "18.234.68.179" | awk '{print $1}' | sort -u > ${OUTPUTFOLDER}/good-v4.ips 
grep "Response" ${OUTPUTFOLDER}/${DATESTR}-v4-resolve-v6.out | grep "2604:a880:2:d0::211b:f001" | awk '{print $1}' | sort -u | grep -F -f - ${OUTPUTFOLDER}/good-v4.ips > tmp
mv tmp good-v4.ips 
grep "Response" ${OUTPUTFOLDER}/${DATESTR}-v6-resolve-v4.out | grep "18.234.68.179" | awk '{print $1}' | sort -u > ${OUTPUTFOLDER}/good-v6.ips 
grep "Response" ${OUTPUTFOLDER}/${DATESTR}-v6-resolve-v6.out | grep "2604:a880:2:d0::211b:f001" | awk '{print $1}' | sort -u | grep -F -f - ${OUTPUTFOLDER}/good-v6.ips > tmp
mv tmp good-v6.ips 
grep -F -f ${OUTPUTFOLDER}/good-v4.ips ${OUTPUTFOLDER}/${DATESTR}-single-resolvers-country-sorted | grep -F -f ${OUTPUTFOLDER}/good-v6.ips > ${OUTPUTFOLDER}/${DATESTR}-single-resolvers-country-correct-sorted
date

echo "Checking Resolver Interface BIND version"
time -p cat ${OUTPUTFOLDER}/${DATESTR}-single-resolvers-country-correct-sorted | /home/timartiny/v4vsv6/check-dns-versions/version > ${OUTPUTFOLDER}/${DATESTR}-single-resolvers-country-matching-version-bind
date 
echo "Make sure to start PCAPing on the machine with the NS for both a v4 and v6 domain befor running 06.sh"
