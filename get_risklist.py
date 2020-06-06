# get_risklist.py
# Created by Patrick Kinsella 6/4/2020
# Last edited 6/5/2020
#
# Takes an API key for the Recorded Future API
# Downloads an IP Risk List and creates a text file suitable for loading
# into Zeek

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

    f = open("zeek_intel.txt", "w")
    f.write("#fields\tindicator\tindicator_type\tmeta.risk\tmeta.riskstring")
    f.write("\tmeta.rule\tmeta.criticalitylabel\tmeta.desc\tmeta.timestamp")
    f.write("\tmeta.name\tmeta.criticality")
    f.write("\n")

    api = ConnectApiClient(auth=args.apikey)
    ip_risklist = api.get_ip_risklist()
    decoding_errors = 0
    total = 0
    for ip in ip_risklist.csv_reader:
        total += 1
        try:
            edict = json.loads(ip['EvidenceDetails'])
            for e in edict['EvidenceDetails']:
                f.write(ip['Name'] + "\tIntel::ADDR\t" + ip['Risk'] + "\t")
                f.write(ip['RiskString'] + "\t")
                f.write(e['Rule'] + "\t" + e['CriticalityLabel'] + "\t")
                f.write(e['EvidenceString'] + "\t" + e['Timestamp'] + "\t")
                f.write(e['Name'] + "\t" + str(e['Criticality']))
                f.write("\n")
        except UnicodeEncodeError:
            decoding_errors += 1
    if decoding_errors > 0:
        print("while parsing the IP risk list, there were ", end="")
        print(str(decoding_errors) + " unicode encoding errors")
    print(str(total - decoding_errors) + " records parsed correctly")
    f.close()
