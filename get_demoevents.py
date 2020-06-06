# get_demoevents.py
# Created by Patrick Kinsella 6/5/2020
# Last edited 6/5/2020
#
# Takes an API key for the Recorded Future API
# Downloads demo event data and creates an input file watchlist.file that,
# along with events.zeek, reads demo events into the Zeek Input Framework

from rfapi import ConnectApiClient
import json
import argparse

if __name__ == '__main__':
    # API key supplied as argument on command line
    # NEVER hardcode an API key, it could be exposed by source control etc >:O
    parser = argparse.ArgumentParser(description='Download and parse Demo\
                                                  Events data from RF for Zeek')
    parser.add_argument('apikey', type=str, help='RF API key for API auth')
    args = parser.parse_args()

    f = open("watchlist.file", "w")
    f.write("#fields\tsrc_ip\tdst_ip\n")

    api = ConnectApiClient(auth=args.apikey)
    demoevents = api.get_ip_demoevents()

    unprocessed_lines = 0
    for event in iter(demoevents.text.splitlines()):
        # str.find() returns lowest index of first matching substring instance
        # dst IP comes before src IP, and src IP is the end of the line
        if (event.find('dst=') == -1 or event.find('src=') == -1):
            unprocessed_lines += 1
        else:
            dst_ip = event[event.find('dst=') + 4 : event.find('src=') - 1]
            src_ip = event[event.find('src=') + 4 :]
        f.write(src_ip + "\t" + dst_ip + "\n")

    if unprocessed_lines > 0:
        print(unprocessed_lines + " could not be processed")
    f.close()
