#! /usr/bin/env python3

from collections import defaultdict
import geoip2.database
import geoip2.errors
import json
import sys

def default_dict_constructor():
    return defaultdict(int)

def print_asn_results(asn_dict, unknown_asns, outfile):
    with open(outfile, 'w') as write_file:
        for key in asn_dict:
            write_file.write(f"{key}: {asn_dict[key]['timeout']} {asn_dict[key]['fine']}\n")
        
        for ip in unknown_asns:
            write_file.write(f"unknown_asn: {ip}\n")

    return

def print_results(counting_dict, db_path, asn_outfile):
    timeoutCount = 0
    weirdCount = 0
    asn_dict = defaultdict(default_dict_constructor)
    unknown_asns = []
    with geoip2.database.Reader(db_path) as reader:
        for k in counting_dict:
            ip = k.split("-")[0]
            try:
                response = reader.asn(ip)
            except geoip2.errors.AddressNotFoundError:
                asn_key = "UnknownASN"
                unknown_asns.append(ip)
            else:
                asn_key = f"{response.autonomous_system_number}-{response.autonomous_system_organization}"
            if counting_dict[k]["seen"] < 3:
                print(f"{k} seen {counting_dict[k]['seen']} times only")

            if counting_dict[k]["seen"] == counting_dict[k]["timeout"]:
                print(k)
                timeoutCount += 1
                asn_dict[asn_key]["timeout"] += 1
            else:
                asn_dict[asn_key]["fine"] += 1
                if counting_dict[k]["timeout"] > 0:
                    weirdCount += 1
    
    print(f"ip-domain timeout rate: {timeoutCount} / {len(counting_dict)} = {timeoutCount/len(counting_dict)}")
    print(f"weird rate: {weirdCount} / {len(counting_dict)} = {weirdCount/len(counting_dict)}")
    print_asn_results(asn_dict, unknown_asns, asn_outfile)

def main():
    counting_dict = {}
    fileName = sys.argv[1]
    with open(fileName, 'r') as dataFile:
        while True:
            line = dataFile.readline()
            if len(line) == 0:
                break
            try:
                lineDict = json.loads(line)
            except json.decoder.JSONDecodeError:
                print("json decoding error")
                print(f"line: {line}")
            keyStr = f"{lineDict['ip']}-{lineDict['domain']}"
            v = counting_dict.get(keyStr)
            if v is None:
                counting_dict[keyStr] = {}
                counting_dict[keyStr]["seen"] = 1
                counting_dict[keyStr]["timeout"] = 0
            else:
                counting_dict[keyStr]["seen"] += 1

            if "i/o timeout" in line:
                counting_dict[keyStr]["timeout"] += 1
    print_results(counting_dict, sys.argv[2], sys.argv[3])
    

if __name__ == "__main__":
    main()