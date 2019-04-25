#!/usr/bin/env python3

# See https://docs.python.org/3.2/library/socketserver.html

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
import argparse
import base64
import csv
import decouple
import io
import os
import re
import socket
import socketserver
import stat
import sys
import threading

def read_csv_as_dicts(filename, keyfield='Name'):
    """Read a CSV file, producing a dictionary for each row.

The rows are held in a dictionary, with the given key (by default,
'Name').
    """
    data = {}
    with io.open(filename, 'r', encoding='utf-8') as instream:
        data_reader = csv.DictReader(instream)
        for row in data_reader:
            data[row[keyfield]] = row
    return data

def read_csv_as_lists(filename, keycolumn=0):
    """Read a CSV file, producing a list for each row.

The rows are held in a dictionary, taking the specified column (0 by
default) for the keys.
    """
    data = {}
    with io.open(filename, 'r', encoding='utf-8') as instream:
        data_reader = csv.reader(instream)
        for row in data_reader:
            data[row[keycolumn]] = row
    return data

class simple_data_server():

    """A pair of TCP and UDP servers for accessing data from some files.

The servers use the same underlying function and data, and this class
provides a place to hold the description of the files used for the
data.

The function `client_server_main' is provided as an easy way to use
this class.

The user specifies a function for getting the result, and a
description of the files to read to get the data.  If the files have
changed since the previous use, they are re-read before the user
function is called.

The file description is a dictionary binding filenames to indications
of how to read the file:

  - a string, meaning to read the file as CSV and produce a dictionary
    of row dictionaries, using the string to select the column to use
    for the keys in the outer dictionary

  - a number, meaning to read the file as CSV and produce a dictionary
    of row lists, with the number selecting the column to use for the
    dictionary keys

  - a tuple of a function and a value to pass as the second argument of
    the function, the first argument being the filename

The query function is called with two arguments:

  - the data from the TCP or UDP input

  - a dictionary binding the basename of each filename to the data
    read from that file

It should return the string to send back over TCP or UDP.

The `query_keys' argument should be either None, or a list of
decryption keys, in which case they will all be tried to see if they
can make sense of the input.  Making sense of the input is defined by
the `shibboleth' argument, which is a regexp to try on the result of
the decryption.  When a decryption result matches the regexp, if a
`shibboleth_group' argument is given, that is used as the match group
to extract the data to give to the query function; if no
`shibboleth_group' is given, the entire decryption result is used.

(The shibboleth arrangement is so that multiple users can use it, each
with their own set of keys, without having to send any non-encrypted
indication of which user's key is to be used.  I don't know whether
this is a normal way to do things; I'm just making it up as I go
along.)

If a `reply_key' is given, it is used to encrypt the reply.

The servers are represented as the threads that hold them, and the
threads hold the query function, for reasons explained in the
docstring of the `service_thread' class.

    """

    def __init__(self,
                 host, port,
                 get_result, files,
                 query_keys=None, reply_key=None,
                 shibboleth=None, shibboleth_group=None):
        # Network
        self.host = host
        self.port = port
        # Data
        self.files_readers = files
        self.files_timestamps = {filename: 0 for filename in files.keys()}
        self.files_data = {os.path.basename(filename): None for filename in files.keys()}
        # Encryption
        self.query_keys = query_keys
        self.shibboleth = re.compile(shibboleth or "^(get|put) ")
        self.shibboleth_group = shibboleth_group
        self.reply_key = reply_key
        # The service threads
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
        """Start the server threads."""
        self.udp_server.start()
        self.tcp_server.start()

    def check_data_current(self):
        """Check for the data files changing, and re-read them if necessary."""
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
                self.files_data[os.path.basename(filename)] = reader(filename, key)
                self.files_timestamps[filename] = now_timestamp

def hybrid_encrypt(plaintext, asymmetric_key):
    # see https://stackoverflow.com/questions/28426102/python-crypto-rsa-public-private-key-with-large-file/28427259
    symmetric_key = Random.new().read(32)
    initialization_vector = Random.new().read(AES.block_size)
    cipher = AES.new(symmetric_key, AES.MODE_CFB, initialization_vector)
    symmetrically_encrypted_payload = initialization_vector + cipher.encrypt(plaintext)
    symmetric_key_and_iv = initialization_vector + symmetric_key
    asymmetrically_encrypted_symmetric_iv_and_key = asymmetric_key.publickey().encrypt(
        symmetric_key_and_iv, 32)[0]
    cipher_text = asymmetrically_encrypted_symmetric_iv_and_key + symmetrically_encrypted_payload
    return base64.b64encode(cipher_text)

def hybrid_decrypt(ciphertext, asymmetric_key):
    # see https://stackoverflow.com/questions/28426102/python-crypto-rsa-public-private-key-with-large-file/28427259
    asymmetrically_encrypted_symmetric_iv_and_key = ciphertext[0:128]
    symmetrically_encrypted_payload = ciphertext[128:]
    symmetric_key_and_iv = asymmetric_key.decrypt(asymmetrically_encrypted_symmetric_iv_and_key)
    initialization_vector = symmetric_key_and_iv[0:AES.block_size]
    symmetric_key = symmetric_key_and_iv[AES.block_size:]
    cipher = AES.new(symmetric_key, AES.MODE_CFB, initialization_vector)
    decrypted_data = cipher.decrypt(symmetrically_encrypted_payload)
    return decrypted_data[16:].decode()

class service_thread(threading.Thread):

    """A wrapper for threads, that passes in a service function.

The rationale for it is that the application-specific handlers passed
to `socketserver.TCPServer' and `socketserver.UDPServer' are classes
rather than class instances, so, as the instantiation of them is done
out of our control, we can't pass in a query function argument.
However, in our query handler, we can find what the current thread is,
so we use the thread (this class) as somewhere to store the function.

    """

    def __init__(self,
                 server,
                 get_result,
                 **rest):
        super().__init__(target=run_server,
                         **rest)
        self.server = server
        self._get_result = get_result

    def get_result(self, data_in):
        """Return the result corresponding to the input argument.

This calls the user-supplied get_result function, using encryption if
specified.  (The user function doesn't need to handle any of the
encryption itself.)

        """
        if self.server.shibboleth.match(data_in):
            # the incoming data made sense as plaintext:
            return self._get_result(data_in, self.server.files_data)
        else:
            # try all the keys that users might have sent things in with:
            decrypted = False
            data_in = base64.b64decode(data_in)
            for qk in self.server.query_keys:
                plaintext = hybrid_decrypt(data_in, qk)
                passed = self.server.shibboleth.match(plaintext)
                if passed:
                    data_in = (passed[self.server.shibboleth_group]
                               if self.server.shibboleth_group
                               else plaintext)
                    decrypted = True
                    break
            if not decrypted:
                print("Could not decrypt incoming message")
                return None
            return hybrid_encrypt(
                    self._get_result(data_in,
                                     self.server.files_data),
                    self.server.reply_key)

class MyTCPHandler(socketserver.StreamRequestHandler):

    """The TCP handler for the simple_data_server class.

It uses the `service_thread' class to determine what to do with the
data.
    """
    
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
        self.wfile.write(
            bytes(str(
                my_thread.get_result(
                    self.rfile.readline().strip().decode('utf-8'))),
                  'utf-8'))

class MyUDPHandler(socketserver.BaseRequestHandler):

    """The UDP handler for the simple_data_server class.

It uses the `service_thread' class to determine what to do with the
data.
    """

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
        reply_socket.sendto(
            bytes(str(
                my_thread.get_result(
                    self.request[0].strip().decode('utf-8'))),
                  'utf-8'),
            self.client_address)

def run_server(server):
    server.serve_forever()

def run_servers(host, port, getter, files,
                query_keys=None, shibboleth=None, shibboleth_group=None,
                reply_key=None):
    """Run TCP and UDP servers.

They apply the getter argument to the incoming queries, using the
specified files.

    """
    my_server = simple_data_server(
        host, port,
        getter, files,
        query_keys=query_keys, reply_key=reply_key,
        shibboleth=shibboleth, shibboleth_group=shibboleth_group)
    my_server.start()

def get_response(query, host, port, tcp=False,
                query_keys=None, reply_key=None):

    """Send your query to the server, and return its result.

This is a client suitable for the simple_data_server class.

If using encryption, the caller should compose the query such that it matches
the shibboleth regexp.
    """
    query = query + "\n"
    if query_keys:
        query = hybrid_encrypt(query, query_keys[0])
    else:
        query = bytes(query, 'utf-8')
    if tcp:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((host, int(port)))
            sock.sendall(query)
            received = str(sock.recv(1024), 'utf-8')
        finally:
            sock.close()
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(query, (host, int(port)))
        received = str(sock.recv(1024), 'utf-8')
    if reply_key:
        received = hybrid_decrypt(base64.b64decode(received),
                                  reply_key)
    return received

def read_key(filename, passphrase=None):
    """Wrap importKey with file opening, for easy use in comprehensions."""
    with open(filename) as reply_stream:
        return RSA.importKey(reply_stream.read(),
                             passphrase=passphrase)

def client_server_main(getter, files):
    """Run a simple client or server.

The argument `getter' is a function to be used by the server to
process the data it gets from the client.  It should take two
arguments, a string and a dictionary binding basenames of filenames to
the result of the reader functions for those file (see below), and
return the result string.

The argument `files' is a dictionary binding filenames to functions
for reading them.  The reading functions may be functions of two args,
one the filename and the other a key, or a tuple of the function and
the key, or a string, in which case it is used as the key for a
built-in reader function using csv.DictReader, or a number, in which
case it is used as the key for a built-in reader function using
csv.reader.

See the documentation of the simple_data_server class, or the
accompanying README.md, for a less terse description.

    """
    parser=argparse.ArgumentParser()
    parser.add_argument('--host', '-H',
                        default="127.0.0.1",
                        help="""The server to handle the query.""")
    parser.add_argument('--port', '-P',
                        default=9999,
                        help="""The port on which to send the query.""")
    parser.add_argument('--server', '-S',
                        action='store_true',
                        help="""Run as the server.
                        Otherwise, it will run as a client.""")
    parser.add_argument("--tcp", "-t",
                        action='store_true',
                        help="""Use a TCP connection to communicate with the server.
                        Otherwise, UDP will be used.
                        Only applies when running as a client; the server does both.""")
    parser.add_argument("--query-key", "-q",
                        action='append',
                        help="""The key files for decrypting the queries.
                        These are public keys, so may be visible to all users.
                        Because the server cannot know which user is sending
                        an encrypted query, it must try the public query keys
                        for all expected users.""")
    parser.add_argument("--shibboleth", "-s",
                        help="""A regexp to detect validly decrypted input.""")
    parser.add_argument("--shibboleth-group", "-g",
                        help="""Which group in the shibboleth regexp contains
                        the actual query.  If not specified, the whole query
                        is used.""")
    parser.add_argument("--reply-key", "-r",
                        default=None,
                        help="""The key file for encrypting the replies.
                        This is a private key, so should be kept unreadable
                        to everyone except the server user.
                        If this is not given, replies are sent in plaintext.""")
    parser.add_argument("--gen-key",
                        help="""Generate a key in the specified file, and its
                        associated public key in that name + '.pub'.
                        No other action is done.""")
    parser.add_argument('data', nargs='*', action='append',
                        help="""The data to send to the server.""")
    args=parser.parse_args()
    reply_key = None
    private_key = args.query_key[0] if args.server else args.reply_key
    query_passphrase = decouple.config('query_passphrase')
    reply_passphrase = decouple.config('reply_passphrase')
    if private_key:
        key_perms = os.stat(private_key).st_mode
        if key_perms & (stat.S_IROTH | stat.S_IRGRP | stat.S_IWOTH | stat.S_IWGRP):
            print("Key file", private_key, "is open to misuse.")
            sys.exit(1)
        reply_key = read_key(args.reply_key, reply_passphrase)
    query_keys = ([read_key(qk, query_passphrase) for qk in args.query_key]
                  if args.query_key and len(args.query_key) > 0
                  else None)
    if args.server:
        run_servers(args.host, int(args.port),
                    getter=getter,
                    files=files,
                    query_keys=query_keys,
                    shibboleth=args.shibboleth,
                    shibboleth_group=(int(args.shibboleth_group)
                                      if args.shibboleth_group
                                      else None),
                    reply_key=reply_key)
    elif args.gen_key:
        passphrase = sys.stdin.readline().strip()
        with open(args.gen_key, 'w') as keystream:
            with open(args.gen_key + ".pub", 'w') as pubkeystream:
                key = RSA.generate(1024, Random.new().read)
                keystream.write(str(key.exportKey(passphrase=passphrase), 'utf-8'))
                pubkeystream.write(str(key.publickey().exportKey(passphrase=passphrase), 'utf-8'))
    else:
        text = " ".join(args.data[0])

        received = get_response(text,
                                args.host, args.port, args.tcp,
                                query_keys=query_keys,
                                reply_key=reply_key)

        print("Sent:     {}".format(text))
        print("Received: {}".format(received))

# Example:

demo_filename = "/var/local/demo/demo-main.csv"

def demo_getter(in_string, files_data):
    """A simple query program that uses the first column in the CSV file
as the key, and returns the whole row."""
    return files_data[os.path.basename(demo_filename)].get(in_string, "Unknown")

def main():
    client_server_main(demo_getter,
                       {demo_filename: 0})

if __name__ == "__main__":
    main()
