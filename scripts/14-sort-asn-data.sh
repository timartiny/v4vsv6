#! /usr/bin/env bash

. ./variables.sh

cat $OUTPUTFOLDER/${DATESTR}_A_asn_data | grep -v "unknown_asn" | awk -F":" '{print $2", " $0}' | sort -k 1nr | sed 's/^.*, //' > $OUTPUTFOLDER/${DATESTR}_A_asn_data_sorted
cat $OUTPUTFOLDER/${DATESTR}_AAAA_asn_data | grep -v "unknown_asn" | awk -F":" '{print $2", " $0}' | sort -k 1nr | sed 's/^.*, //' > $OUTPUTFOLDER/${DATESTR}_AAAA_asn_data_sorted
