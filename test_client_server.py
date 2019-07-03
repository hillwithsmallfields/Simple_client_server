#!/usr/bin/env python3

import argparse
import decouple
import os

import client_server

csv_demo_filename = "/var/local/demo/demo-main.csv"
csv_headed_demo_filename = "/var/local/demo/demo-main-headed.csv"
json_demo_filename = "/var/local/demo/demo-main.json"

def demo_getter_csv_0(in_string, files_data):
    """A simple query program for CSV files.

    It uses the first column in the CSV file as the key, and returns
    the whole row.
    """
    return str(files_data[os.path.basename(csv_demo_filename)]
               .get(in_string.strip().split()[0],
                    ["Unknown"]))

def demo_getter_csv_name(in_string, files_data):
    """A simple query program for CSV files.

    It uses the name column in the CSV file as the key, and returns
    the whole row.
    """
    return str(files_data[os.path.basename(csv_headed_demo_filename)]
               .get(in_string.strip().split()[0],
                    ["Unknown"]))

def demo_getter_json(in_string, files_data):
    """A simple query program for JSON files.

    It assumes the file contains a dictionary at the top level.
    """
    return (files_data[os.path.basename(json_demo_filename)]
            .get(in_string.strip().split()[0],
                 ["Unknown"]))

def run_test_queries(text, args, csv_0_port, csv_name_port, json_port, query_key, reply_key, files, use_tcp):
    print("Sending csv_0 query with", "tcp" if use_tcp else "udp")
    received = client_server.get_response(
        text,
        args.host, csv_0_port, use_tcp,
        encryption_scheme=ord('H'
                              if query_key and reply_key
                              else 'p'),
        query_key=query_key,
        reply_key=reply_key)
    print("Sent:     {}".format(text))
    print("Received: {}".format(received))

    print("Sending csv_name query with", "tcp" if use_tcp else "udp")
    received = client_server.get_response(
        text,
        args.host, csv_name_port, use_tcp,
        encryption_scheme=ord('H'
                              if query_key and reply_key
                              else 'p'),
        representation_scheme=ord('j'),
        query_key=query_key,
        reply_key=reply_key)
    print("Sent:     {}".format(text))
    print("Received: {}".format(received))

    print("Sending json query with", "tcp" if use_tcp else "udp")
    received = client_server.get_response(
        text,
        args.host, json_port, use_tcp,
        encryption_scheme=ord('H'
                              if query_key and reply_key
                              else 'p'),
        query_key=query_key,
        reply_key=reply_key)
    print("Sent:     {}".format(text))
    print("Received: {}".format(received), "of type", type(received))

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--server', '-S',
                        action='store_true',
                        help="""Run as the server.
                        Otherwise, it will run as a client.""")
    parser.add_argument('data', nargs='*', action='append',
                        help="""The data to send to the server.""")
    client_server.client_server_add_arguments(parser, port=9000)
    args=parser.parse_args()
    query_passphrase = decouple.config('query_passphrase')
    reply_passphrase = decouple.config('reply_passphrase')
    client_server.check_private_key_privacy(args)
    query_key, reply_key = client_server.read_keys_from_files(args,
                                                              query_passphrase,
                                                              reply_passphrase)

    csv_0_port = int(args.port)
    csv_name_port = csv_0_port + 1
    json_port = csv_name_port + 1
    files = {"demo-main.csv": 0,
             "demo-main-headed.csv": "name",
             "demo-main.json": None}

    if args.server:
        print("starting csv_0 server")
        client_server.run_servers(args.host, csv_0_port,
                                  getter=demo_getter_csv_0,
                                  files=files,
                                  query_key=query_key,
                                  reply_key=reply_key)
        print("started csv_0 server; starting csv_name server")
        client_server.run_servers(args.host, csv_name_port,
                                  getter=demo_getter_csv_name,
                                  files=files,
                                  query_key=query_key,
                                  reply_key=reply_key)
        print("started csv_name server; starting json server")
        client_server.run_servers(args.host, json_port,
                                  getter=demo_getter_json,
                                  files=files,
                                  query_key=query_key,
                                  reply_key=reply_key)
        print("started json server")

    else:
        text = " ".join(args.data[0])

        print("query text is", text)

        run_test_queries(text, args, csv_0_port, csv_name_port, json_port, query_key, reply_key, files, False)
        run_test_queries(text, args, csv_0_port, csv_name_port, json_port, query_key, reply_key, files, True)

if __name__ == "__main__":
    main()
