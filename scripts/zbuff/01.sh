#! /usr/bin/env bash

. ./variables.sh

date
echo "Running zmap scan over udp port 53 doing a lookup for v4vsv6.com"
time -p sudo /home/timartiny/zmap/src/zmap -S 192.12.240.41 -B 1G -M udp -p 53 --probe-args=file:v4vsv6.com.pkt -o ${OUTPUTFOLDER}/${DATESTR}-zmap.csv
date
echo "Before running 02.sh make sure to start pcaping on v6 Name Server"

