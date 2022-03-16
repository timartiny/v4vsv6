#! /usr/bin/env bash

. ./variables.sh

tcpdump -n -i eth0 ip6 and udp port 53 -w $OUTPUTFOLDER/$DATESTR-v6.pcap
