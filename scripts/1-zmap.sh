#! /usr/bin/env bash

. ./variables.sh

sudo zmap -B 1G -p 53 -o $OUTPUTFOLDER/$DATESTR-zmap.csv
# sudo zmap -p 53 -n 10000 -o $OUTPUTFOLDER/$DATESTR-zmap.csv
