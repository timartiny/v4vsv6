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
            write_file.write("{}: {} {}\n".format(key, asn_dict[key]['timeout'], asn_dict[key]['fine']))
        
        for ip in unknown_asns:
            write_file.write("unknown_asn: {}\n".format(ip))

    return

def print_results(counting_dict, db_path, asn_outfile, expected_count, retry_file):
    timeoutCount = 0
    weirdCount = 0
    asn_dict = defaultdict(default_dict_constructor)
    unknown_asns = []
    with geoip2.database.Reader(db_path) as reader:
        with open(retry_file, 'w+') as writer:
            for k in counting_dict:
                ip = k.split("-")[0]
                try:
                    response = reader.asn(ip)
                except geoip2.errors.AddressNotFoundError:
                    asn_key = "UnknownASN"
                    unknown_asns.append(ip)
                else:
                    asn_key = "{}-{}".format(response.autonomous_system_number, response.autonomous_system_organization)
                if counting_dict[k]["seen"] < expected_count:
                    print("{} seen {} times only".format(k, counting_dict[k]['seen']))

                if counting_dict[k]["seen"] == counting_dict[k]["timeout"]:
                    print(k)
                    split = k.split("-")
                    writer.write("{}, {}\n".format(split[0], split[1]))
                    timeoutCount += 1
                    asn_dict[asn_key]["timeout"] += 1
                else:
                    asn_dict[asn_key]["fine"] += 1
                    if counting_dict[k]["timeout"] > 0:
                        weirdCount += 1
    
    print("ip-domain timeout rate: {} / {} = {}".format(timeoutCount, len(counting_dict), timeoutCount/len(counting_dict)))
    print("weird rate: {} / {} = {}".format(weirdCount, len(counting_dict), weirdCount/len(counting_dict)))
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
                print("line: {}".format(line))
            keyStr = "{}-{}".format(lineDict['ip'], lineDict['domain'])
            v = counting_dict.get(keyStr)
            if v is None:
                counting_dict[keyStr] = {}
                counting_dict[keyStr]["seen"] = 1
                counting_dict[keyStr]["timeout"] = 0
            else:
                counting_dict[keyStr]["seen"] += 1

            if "i/o timeout" in line:
                counting_dict[keyStr]["timeout"] += 1
    print_results(counting_dict, sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5])
    

if __name__ == "__main__":
    main()
