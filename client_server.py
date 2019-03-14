#!/usr/bin/env python3

# See https://docs.python.org/3.2/library/socketserver.html

import argparse
import csv
import datetime
import io
import os
import socket
import socketserver
import threading

def read_csv_as_lists(filename):
    data = {}
    with io.open(filename, 'r', encoding='utf-8') as input:
        data_reader = csv.reader(input)
        for row in data_reader:
            data[row[0]] = row
    return data

class simple_data_server():

    def __init__(self, files):
        self.files_readers = files
        self.files_data = {filename: (0, None) for filename in files.keys()}

    def check_data_current(self):
        for filename, timestamped_data in self.files_data.items():
            timestamp = os.path.getctime(filename)
            if timestamp > timestamped_data[0]:
                self.files_data[filename] = (
                    timestamp,
                    (self.files_readers.get(filename, None)
                     or read_csv_as_lists)(filename))

    def get_result(self, input):
        """Return the result corresponding to the input argument."""
        self.check_data_current()
        return ",".join(self.files_data[main_filename][1].get(input,
                                                              [None, "unknown"])[1:])

main_filename = "/var/local/demo/demo-main.csv"

my_server = simple_data_server({main_filename: None})

def get_result(query):
    return my_server.get_result(query)

class MyTCPHandler(socketserver.StreamRequestHandler):

    def __init__(self,
                 # service,
                 *rest):
        print("MyTCPHandler", rest)
        super().__init__(*rest)
        self.allow_reuse_address = True
        # self.service = service

    def handle(self):
        self.data = self.rfile.readline().strip()
        # todo: I want to call self.service.get_result, but what is passed when MyTCPHandler is specified is the class object, not an instance, so the service can't be passed in for creating it
        self.wfile.write(bytes(get_result(self.data.decode('utf-8')),
                               'utf-8'))

class MyUDPHandler(socketserver.BaseRequestHandler):

    def __init__(self,
                 # service,
                 *rest):
        print("MyUDPHandler", rest)
        super().__init__(*rest)
        self.allow_reuse_address = True
        # self.service = service

    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        socket.sendto(bytes(get_result(data.decode('utf-8')),
                            'utf-8'),
                      self.client_address)

def run_server(server):
    server.serve_forever()

def run_servers(host, port):
    threading.Thread(target=run_server,
                     args=[socketserver.UDPServer((host, port),
                                                  MyUDPHandler)]).start()

    threading.Thread(target=run_server,
                     args=[socketserver.TCPServer((host, port),
                                                  MyTCPHandler)]).start()

def get_response(query, host, port, tcp=False):
    if tcp:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            to_send = bytes(query + "\n", "utf-8")
            sock.connect((host, int(port)))
            sock.sendall(to_send)
            received = str(sock.recv(1024), "utf-8")
        finally:
            sock.close()
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(bytes(query, 'utf-8'), (host, int(port)))
        received = str(sock.recv(1024), "utf-8")
    return received

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--host', '-H', default="127.0.0.1")
    parser.add_argument('--port', '-P', default=9999)
    parser.add_argument('--server', '-S', action='store_true',
                        help="""Run as the server.
                        Otherwise, it will run as a client.""")
    parser.add_argument("--tcp", "-t", action='store_true',
                        help="""Use a TCP connection to communicate with the server.
                        Otherwise, UDP will be used.
                        Only applies when running as a client; the server does both.""")
    parser.add_argument('data', nargs='*', action='append',
                        help="""The data to send to the server.""")
    args=parser.parse_args()
    if args.server:
        run_servers(args.host, int(args.port))
    else:
        text = " ".join(args.data[0])

        received = get_response(text, args.host, args.port, args.tcp)

        print("Sent:     {}".format(text))
        print("Received: {}".format(received))

if __name__ == "__main__":
    main()
