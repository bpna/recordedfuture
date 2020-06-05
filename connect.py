from rfapi import ConnectApiClient
import json
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Download and parse IP Risk\
                                                  List data from RF for Zeek')
    parser.add_argument('api key', type=str, help='RF API key for API auth')
    args = parser.parse_args()
    api = ConnectApiClient(auth=args['api key'])
    rl = api.get_ip_risklist()
    # for row in rl.csv_reader:
