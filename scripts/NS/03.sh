#! /usr/bin/env bash

. ./variables.sh

tcpdump -n -i eth0 udp port 53 -w $OUTPUTFOLDER/$DATESTR-preference.pcap
