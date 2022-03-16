#! /usr/bin/env bash
. ./variables.sh
sudo tcpdump -n  -w $OUTPUTFOLDER/$DATESTR-A-day2.pcap
