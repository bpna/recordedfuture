# get_risklist.py
# Created by Patrick Kinsella 6/4/2020
# Last edited 6/7/2020
#
# Takes an API key for the Recorded Future API
# Downloads an IP Risk List and creates a input file zeek_intel.txt suitable for
# loading into the Zeek Intelligence Framework

from rfapi import ConnectApiClient
import json
import argparse

if __name__ == '__main__':
    # API key supplied as argument on command line
    # NEVER hardcode an API key, it could be exposed by source control etc >:O
    parser = argparse.ArgumentParser(description='Download and parse IP Risk\
                                                  List data from RF for Zeek')
    parser.add_argument('apikey', type=str, help='RF API key for API auth')
    args = parser.parse_args()

    # Create zeek_intel column names
    f = open("zeek_intel.txt", "w")
    f.write("#fields\tindicator\tindicator_type\tmeta.source\tmeta.risk")
    f.write("\tmeta.riskstring\tmeta.rule\tmeta.criticalitylabel\tmeta.desc")
    f.write("\tmeta.timestamp\tmeta.name\tmeta.criticality\n")

    # Get and parse IP risk list from RF
    api = ConnectApiClient(auth=args.apikey)
    ip_risklist = api.get_ip_risklist()
    decoding_errors = 0
    total = 0
    for ip in ip_risklist.csv_reader:
        total += 1
        try:
            edict = json.loads(ip['EvidenceDetails'])
            for e in edict['EvidenceDetails']:
                f.write(ip['Name'] + "\tIntel::ADDR\tRFAPI\t" + ip['Risk'])
                f.write("\t" + ip['RiskString'] + "\t")
                f.write(e['Rule'] + "\t" + e['CriticalityLabel'] + "\t")
                f.write(e['EvidenceString'] + "\t" + e['Timestamp'] + "\t")
                f.write(e['Name'] + "\t" + str(e['Criticality']))
                f.write("\n")
        except UnicodeEncodeError:
            decoding_errors += 1

    # Print status output, cannot handle UnicodeEncodeErrors at present
    if decoding_errors > 0:
        print("while parsing the IP risk list, there were ", end="")
        print(str(decoding_errors) + " unicode encoding errors")
    print(str(total - decoding_errors) + " records parsed correctly")
    f.close()
