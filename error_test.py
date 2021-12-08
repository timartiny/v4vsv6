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
    errorCount = 0
    connectionRefusedCount = 0
    connectionResetCount = 0
    i_o_timeoutCount = 0
    networkUnreachableCount = 0
    remoteInternalErrorCount = 0
    noRouteToHostCount = 0
    unexpectedEOFCount = 0
    contextDeadlineExceededCount = 0
    oversized20527Count = 0
    EOFCount = 0
    remoteHandshakeFailureCount = 0
    oversized29805Count = 0
    alert112Count = 0
    weirdCount = 0
    permissionDeniedCount = 0
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

                seenCount = counting_dict[k]["seen"]
                if seenCount == counting_dict[k]["error"]:
                    split = k.split("-")
                    writer.write("{}, {}\n".format(split[0], split[1]))
                    errorCount += 1
                    asn_dict[asn_key]["error"] += 1
                else:
                    asn_dict[asn_key]["fine"] += 1
                    if counting_dict[k]["error"] > 0:
                        weirdCount += 1
                if seenCount == counting_dict[k]["connection_refused"]:
                    connectionRefusedCount += 1
                elif seenCount == counting_dict[k]["connection_reset"]:
                    connectionResetCount += 1
                elif seenCount == counting_dict[k]["i/o-timeout"]:
                    i_o_timeoutCount += 1
                elif seenCount == counting_dict[k]["network_unreachable"]:
                    networkUnreachableCount += 1
                elif seenCount == counting_dict[k]["remote_error_internal_error"]:
                    remoteInternalErrorCount += 1
                elif seenCount == counting_dict[k]["no_route_to_host"]:
                    noRouteToHostCount += 1
                elif seenCount == counting_dict[k]["unexpected_eof"]:
                    unexpectedEOFCount += 1
                elif seenCount == counting_dict[k]["context_deadline_exceeded"]:
                    contextDeadlineExceededCount += 1
                elif seenCount == counting_dict[k]["oversized_20527"]:
                    oversized20527Count += 1
                elif seenCount == counting_dict[k]["EOF"]:
                    EOFCount += 1
                elif seenCount == counting_dict[k]["remote_error_handshake_failure"]:
                    remoteHandshakeFailureCount += 1
                elif seenCount == counting_dict[k]["oversized_29805"]:
                    oversized29805Count += 1
                elif seenCount == counting_dict[k]["alert_112"]:
                    alert112Count += 1
                elif seenCount == counting_dict[k]["permission_denied"]:
                    permissionDeniedCount += 1
    
    dictSize = len(counting_dict)
    print("ip-domain connection refused rate: {} / {} = {}".format(connectionRefusedCount, dictSize, connectionRefusedCount/dictSize))
    print("ip-domain connection reset rate: {} / {} = {}".format(connectionResetCount, dictSize, connectionResetCount/dictSize))
    print("ip-domain i/o timeout rate: {} / {} = {}".format(i_o_timeoutCount, dictSize, i_o_timeoutCount/dictSize))
    print("ip-domain network unreachable rate: {} / {} = {}".format(networkUnreachableCount, dictSize, networkUnreachableCount/dictSize))
    print("ip-domain remote error: internal error rate: {} / {} = {}".format(remoteInternalErrorCount, dictSize, remoteInternalErrorCount/dictSize))
    print("ip-domain no route to host rate: {} / {} = {}".format(noRouteToHostCount, dictSize, noRouteToHostCount/dictSize))
    print("ip-domain unexpected EOF rate: {} / {} = {}".format(unexpectedEOFCount, dictSize, unexpectedEOFCount/dictSize))
    print("ip-domain context deadline exceeded rate: {} / {} = {}".format(contextDeadlineExceededCount, dictSize, contextDeadlineExceededCount/dictSize))
    print("ip-domain oversized 20527 rate: {} / {} = {}".format(oversized20527Count, dictSize, oversized20527Count/dictSize))
    print("ip-domain EOF rate: {} / {} = {}".format(EOFCount, dictSize, EOFCount/dictSize))
    print("ip-domain remote error: handshake failure rate: {} / {} = {}".format(remoteHandshakeFailureCount, dictSize, remoteHandshakeFailureCount/dictSize))
    print("ip-domain oversized 29805 rate: {} / {} = {}".format(oversized29805Count, dictSize, oversized29805Count/dictSize))
    print("ip-domain alert 112 rate: {} / {} = {}".format(alert112Count, dictSize, alert112Count/dictSize))
    print("ip-domain permission denied rate: {} / {} = {}".format(permissionDeniedCount, dictSize, permissionDeniedCount/dictSize))
    print("weird rate: {} / {} = {}".format(weirdCount, dictSize, weirdCount/dictSize))
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
                counting_dict[keyStr]["error"] = 0
                counting_dict[keyStr]["connection_refused"] = 0
                counting_dict[keyStr]["connection_reset"] = 0
                counting_dict[keyStr]["i/o-timeout"] = 0
                counting_dict[keyStr]["network_unreachable"] = 0
                counting_dict[keyStr]["remote_error_internal_error"] = 0
                counting_dict[keyStr]["no_route_to_host"] = 0
                counting_dict[keyStr]["unexpected_eof"] = 0
                counting_dict[keyStr]["context_deadline_exceeded"] = 0
                counting_dict[keyStr]["oversized_20527"] = 0
                counting_dict[keyStr]["EOF"] = 0
                counting_dict[keyStr]["remote_error_handshake_failure"] = 0
                counting_dict[keyStr]["oversized_29805"] = 0
                counting_dict[keyStr]["alert_112"] = 0
                counting_dict[keyStr]["permission_denied"] = 0
            else:
                counting_dict[keyStr]["seen"] += 1

            if "connection refused" in line:
                counting_dict[keyStr]["connection_refused"] += 1
            elif "connection reset by peer" in line:
                counting_dict[keyStr]["connection_reset"] += 1
            elif "i/o timeout" in line:
                counting_dict[keyStr]["i/o-timeout"] += 1
            elif "network is unreachable" in line:
                counting_dict[keyStr]["network_unreachable"] += 1
            elif "remote error: internal error" in line:
                counting_dict[keyStr]["remote_error_internal_error"] += 1
            elif "no route to host" in line:
                counting_dict[keyStr]["no_route_to_host"] += 1
            elif "unexpected EOF" in line:
                counting_dict[keyStr]["unexpected_eof"] += 1
            elif "context deadline exceeded" in line:
                counting_dict[keyStr]["context_deadline_exceeded"] += 1
            elif "oversized record received with length 20527" in line:
                counting_dict[keyStr]["oversized_20527"] += 1
            elif "EOF" in line:
                counting_dict[keyStr]["EOF"] += 1
            elif "remote error: handshake failure" in line:
                counting_dict[keyStr]["remote_error_handshake_failure"] += 1
            elif "oversized record received with length 29805" in line:
                counting_dict[keyStr]["oversized_29805"] += 1
            elif "alert(112)" in line:
                counting_dict[keyStr]["alert_112"] += 1
            elif "connect: permission denied" in line:
                counting_dict[keyStr]["permission_denied"] += 1
            elif lineDict["data"]["tls"]["status"] != "success":
                print("Non success case not yet categorized")
                print(line)
            if lineDict["data"]["tls"]["status"] != "success":
                counting_dict[keyStr]["error"] += 1
    print_results(counting_dict, sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5])
    

if __name__ == "__main__":
    main()
