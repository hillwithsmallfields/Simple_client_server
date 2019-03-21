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

def read_csv_as_dicts(filename, keyfield):
    data = {}
    with io.open(filename, 'r', encoding='utf-8') as instream:
        data_reader = csv.DictReader(instream)
        for row in data_reader:
            data[row[keyfield]] = row
    return data

def read_csv_as_lists(filename, keycolumn=0):
    data = {}
    with io.open(filename, 'r', encoding='utf-8') as instream:
        data_reader = csv.reader(instream)
        for row in data_reader:
            data[row[keycolumn]] = row
    return data

class simple_data_server():

    def __init__(self, host, port, get_result, files):
        self.host = host
        self.port = port
        self.files_readers = files
        # todo: put the timestamps into a separate dictionary
        self.files_timestamps = {filename: 0 for filename in files.keys()}
        self.files_data = {filename: None for filename in files.keys()}
        self.udp_server=service_thread(
            args=[socketserver.UDPServer((self.host, self.port),
                                         MyUDPHandler)],
            server=self,
            get_result=get_result)
        self.tcp_server = service_thread(
            args=[socketserver.TCPServer((self.host, self.port),
                                         MyTCPHandler)],
            server=self,
            get_result=get_result)

    def start(self):
        self.udp_server.start()
        self.tcp_server.start()

    def check_data_current(self):
        for filename, timestamp in self.files_timestamps.items():
            now_timestamp = os.path.getctime(filename)
            if now_timestamp > timestamp:
                reader = self.files_readers.get(filename, None)
                if isinstance(reader, str):
                    key = reader
                    reader = read_csv_as_dicts
                elif isinstance(reader, int):
                    key = reader
                    reader = read_csv_as_lists
                elif type(reader) == tuple:
                    key = reader[1]
                    reader = reader[0]
                else:
                    key = None
                self.files_data[filename] = reader(filename, key)
                self.files_timestamps[filename] = now_timestamp

class service_thread(threading.Thread):
    """A wrapper for threads, that passes in a service function."""

    def __init__(self,
                 server,
                 get_result,
                 **rest):
        super().__init__(target=run_server,
                         **rest)
        self.server = server
        self.get_result = get_result

    def get_result(self, data_in):
        """Return the result corresponding to the input argument."""
        return self._get_result(data_in, self.server.files_data)

class MyTCPHandler(socketserver.StreamRequestHandler):

    def __init__(self,
                 # service,
                 *rest):
        super().__init__(*rest)
        self.allow_reuse_address = True
        # self.service = service

    def handle(self):
        my_thread = threading.current_thread()
        my_thread.server.check_data_current()
        my_server = my_thread.server
        self.wfile.write(bytes(str(my_thread.get_result(
            self.rfile.readline().strip().decode('utf-8'),
            my_server.files_data)),
                               'utf-8'))

class MyUDPHandler(socketserver.BaseRequestHandler):

    def __init__(self,
                 # service,
                 *rest):
        super().__init__(*rest)
        self.allow_reuse_address = True
        # self.service = service

    def handle(self):
        reply_socket = self.request[1]
        my_thread = threading.current_thread()
        my_server = my_thread.server
        my_server.check_data_current()
        reply_socket.sendto(bytes(str(my_thread.get_result(
            self.request[0].strip().decode('utf-8'),
            my_server.files_data)),
                            'utf-8'),
                      self.client_address)

def run_server(server):
    server.serve_forever()

def run_servers(host, port, getter, files):
    my_server = simple_data_server(
        host, port,
        getter,
        files)
    my_server.start()

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

def client_server_main(getter, files):
    """Run a simple client or server.

The argument `getter' is a function to be used by the server to
process the data it gets from the client.  It should take two
arguments, a string and a dictionary binding filenames to the result
of the reader functions for those file (see below), and return the
result string.

The argument `files' is a dictionary binding filenames to functions
for reading them.  The reading functions may be functions of two args,
one the filename and the other a key, or a tuple of the function and
the key, or a string, in which case it is used as the key for a
built-in reader function using csv.DictReader, or a number, in which
case it is used as the key for a built-in reader function using
csv.reader.

    """
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
        run_servers(args.host, int(args.port),
                    getter=getter,
                    files=files)
    else:
        text = " ".join(args.data[0])

        received = get_response(text, args.host, args.port, args.tcp)

        print("Sent:     {}".format(text))
        print("Received: {}".format(received))

# Example:
        
demo_filename = "/var/local/demo/demo-main.csv"

def sample_getter(in_string, files_data):
    return files_data[demo_filename].get(in_string, "Unknown")

def main():
    client_server_main(sample_getter,
                       {demo_filename: 0})

if __name__ == "__main__":
    main()
