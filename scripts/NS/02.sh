#! /usr/bin/env bash

. ./variables.sh

tcpdump -n -i eth0 ip and udp port 53 -w $OUTPUTFOLDER/$DATESTR-v4.pcap
