#! /usr/bin/env python3

import json
import sys

def print_results(counting_dict):
    timeoutCount = 0
    weirdCount = 0
    for k in counting_dict:
        if counting_dict[k]["seen"] < 3:
            print(f"{k} seen {counting_dict[k]['seen']} times only")
        if counting_dict[k]["seen"] == counting_dict[k]["timeout"]:
            print(k)
            timeoutCount += 1
        elif counting_dict[k]["timeout"] > 0:
            weirdCount += 1
    
    print(f"ip-domain timeout rate: {timeoutCount} / {len(counting_dict)} = {timeoutCount/len(counting_dict)}")
    print(f"weird rate: {weirdCount} / {len(counting_dict)} = {weirdCount/len(counting_dict)}")

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
            v = counting_dict.get(f"{lineDict['ip']}-{lineDict['domain']}")
            if v is None:
                counting_dict[f"{lineDict['ip']}-{lineDict['domain']}"] = {}
                counting_dict[f"{lineDict['ip']}-{lineDict['domain']}"]["seen"] = 1
                counting_dict[f"{lineDict['ip']}-{lineDict['domain']}"]["timeout"] = 0
            else:
                counting_dict[f"{lineDict['ip']}-{lineDict['domain']}"]["seen"] += 1

            if "i/o timeout" in line:
                counting_dict[f"{lineDict['ip']}-{lineDict['domain']}"]["timeout"] += 1
    print_results(counting_dict)
    

if __name__ == "__main__":
    main()