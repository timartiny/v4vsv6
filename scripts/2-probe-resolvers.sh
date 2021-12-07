#! /usr/bin/env bash
. ./variables.sh
/home/ewust/v6censorship/probe-dns/probe -domain v6.tlsfingerprint.io -workers 1000 -prefix < $OUTPUTFOLDER/$DATESTR-zmap.csv > $OUTPUTFOLDER/$DATESTR.probe.out
# /home/ewust/v6censorship/probe-dns/probe -domain v6.tlsfingerprint.io -workers 25 -prefix < /data/timartiny/v4vsv6/nov-run/head-bq.csv > /data/timartiny/v4vsv6/nov-run/nov-12.probe.out
