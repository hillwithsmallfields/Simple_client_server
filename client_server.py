#!/usr/bin/env python3

# A simple socket-based client and server program, with optional
# encryption, deliberately avoiding the complexity and overhead of
# SSL/TLS, for adapting for your particular needs.

# It can run as either the client or the server, and can use either
# UDP or TCP.  As a client, it sends a request to the server and waits
# for a response.  As a server, it responds to client requests by
# applying a user-supplied function to data read from files.  It
# specifically doesn't use any kind of handshake or back-and-forth
# protocol: for each request, one message goes from client to server,
# and one message from server to client.  If using encryption, two
# pre-shared key pairs are needed: one with the private key on the
# server, to decrypt the request; and one with the private key on the
# client, to decrypt the reply.

# The data-handling part handles re-reading files when they change,
# and is biased towards reading CSV files, as that is what I wanted
# for my original application of this.

# I wrote this in this form because I couldn't find any single example
# that did all the pieces of what I wanted.  I hope it is of
# "examplary" quality for people to base their programs on, but I'm
# awaiting feedback on that.

# Example application scenario: the program runs as a server on my
# home server (a Raspberry Pi) and reads a CSV file containing an
# inventory of my possessions, with shelf/box/cupboard numbers, and a
# CSV file describing the locations, and tells me where something
# should be.  An Android app (which I haven't yet written) will fetch
# completions as I enter the name of something I'm trying to find, and
# then tell me where the thing is supposedly stored; or will scan the
# asset tag barcode (yes, I'm that nerdy) on something I'm holding,
# and tell me which box or shelf I should return it to.

# See:
# - https://docs.python.org/3.2/library/socketserver.html
# - https://stackoverflow.com/questions/28426102/python-crypto-rsa-public-private-key-with-large-file/28427259

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
import argparse
import base64
import csv
import decouple
import io
import os
import socket
import socketserver
import stat
import sys
import threading

#### Handling the underlying data ####

def read_csv_as_dicts(filename, keyfield='Name'):
    """Read a CSV file, producing a dictionary for each row.

The rows are held in a dictionary, with the given key (by default,
'Name').
    """
    with io.open(filename, 'r', encoding='utf-8') as instream:
        return { row[keyfield]: row for row in csv.DictReader(instream) }

def read_csv_as_lists(filename, keycolumn=0):
    """Read a CSV file, producing a list for each row.

The rows are held in a dictionary, taking the specified column (0 by
default) for the keys.
    """
    with io.open(filename, 'r', encoding='utf-8') as instream:
        return { row[keycolumn]: row for row in csv.reader(instream) }

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

The servers are represented as the threads that hold them, and the
threads hold the query function, for reasons explained in the
docstring of the `service_thread' class.

Four versioning bytes are included in the protocol, in case someone
produces incompatible versions later.  For now, only the encryption
version is used.

    """

    def __init__(self,
                 host, port,
                 get_result, files,
                 query_key=None, reply_key=None):
        # Network
        self.host = host
        self.port = port
        # Data
        self.files_readers = files
        self.files_timestamps = {filename: 0
                                 for filename in files.keys()}
        self.files_data = {os.path.basename(filename): None
                           for filename in files.keys()}
        # Encryption
        self.query_key = query_key
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
                self.files_data[os.path.basename(filename)] = reader(filename,
                                                                     key)
                self.files_timestamps[filename] = now_timestamp

#### encryption and decryption ####

def hybrid_encrypt(plaintext, asymmetric_key):
    """Encrypt the plaintext, using a randomly generated symmetric key.

The symmetric key is encrypted with the given asymmetric_key, and that
encrypted key is returned, with the encrypted input appended.
    """
    symmetric_key = Random.new().read(32)
    initialization_vector = Random.new().read(AES.block_size)
    cipher = AES.new(symmetric_key, AES.MODE_CFB, initialization_vector)
    symmetrically_encrypted_payload = (initialization_vector
                                       + cipher.encrypt(plaintext))
    asymmetrically_encrypted_symmetric_iv_and_key = asymmetric_key.publickey().encrypt(
        initialization_vector + symmetric_key, 32)[0]
    return (asymmetrically_encrypted_symmetric_iv_and_key
            + symmetrically_encrypted_payload)

def hybrid_decrypt(ciphertext, asymmetric_key):
    """Use the asymmetric key to decrypt a symmetric key at the start of the ciphertext.

That key is then used to decrypt the rest of the ciphertext.
    """
    asymmetrically_encrypted_symmetric_iv_and_key = ciphertext[:128]
    symmetrically_encrypted_payload = ciphertext[128:]
    symmetric_key_and_iv = asymmetric_key.decrypt(asymmetrically_encrypted_symmetric_iv_and_key)[:48]
    initialization_vector = symmetric_key_and_iv[:AES.block_size]
    symmetric_key = symmetric_key_and_iv[AES.block_size:]
    cipher = AES.new(symmetric_key, AES.MODE_CFB, initialization_vector)
    decrypted_data = cipher.decrypt(symmetrically_encrypted_payload)
    return decrypted_data[16:].decode()

def hybrid_encrypt_base64(plaintext, asymmetric_key):
    """As for hybrid_encrypt but the output is base64-encoded."""
    return base64.b64encode(hybrid_encrypt(plaintext, asymmetric_key))

def hybrid_decrypt_base64(ciphertext, asymmetric_key):
    """As for hybrid_decrypt but the input is base64-encoded."""
    return hybrid_decrypt(base64.b64decode(ciphertext), asymmetric_key)

def null_encrypt(plaintext, _):
    """A function for not encrypting at all."""
    return plaintext

def null_decrypt(ciphertext, _):
    """A function for not decrypting at all."""
    return ciphertext

class UnknownEncryptionType(Exception):
    pass

encryptors = [ null_encrypt,    # 0
               hybrid_encrypt,  # 1
               hybrid_encrypt_base64 # 2
]
decryptors = [ null_decrypt,    # 0
               hybrid_decrypt,  # 1
               hybrid_decrypt_base64 # 2
]

def encrypt(plaintext, key, encryption_scheme):
    if encryption_scheme >= len(encryptors):
        raise(UnknownEncryptionType)
    return encryptors[encryption_scheme](plaintext, key)

def decrypt(ciphertext, key, encryption_scheme):
    if encryption_scheme >= len(decryptors):
        raise(UnknownEncryptionType)
    return decryptors[encryption_scheme](ciphertext, key)

#### Tying the query handler to the server classes ####

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

    def get_result(self, data_in,
                   protocol_version=0, encryption_version=0,
                   authentication_version=0, application_version=0):
        """Return the result corresponding to the input argument.

This calls the user-supplied get_result function, using encryption if
specified.  (The user function doesn't need to handle any of the
encryption itself.)

        """
        return encrypt(self._get_result(decrypt(data_in,
                                                self.server.query_key,
                                                encryption_version),
                                        self.server.files_data),
                       self.server.reply_key,
                       encryption_version)

    def process_request(this, incoming):
        (protocol_version, encryption_version, authentication_version,
         application_version) = incoming[:4]
        incoming = incoming[4:].strip().decode('utf-8')
        this.server.check_data_current()
        result = this.get_result(
            incoming,
            protocol_version, encryption_version,
            authentication_version, application_version)
        if type(result) != bytes:
            result = bytes(result, 'utf-8')
        version_data = bytes((protocol_version, encryption_version,
                              authentication_version, application_version))
        return version_data + result

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
        self.wfile.write(threading.current_thread().process_request(self.rfile.readline().strip().decode('utf-8')))

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
        reply_socket.sendto(
            threading.current_thread().process_request(self.request[0]),
            self.client_address)

#### High-level functions ####

def run_server(server):
    server.serve_forever()

def run_servers(host, port, getter, files,
                query_key=None,
                reply_key=None):
    """Run TCP and UDP servers.

They apply the getter argument to the incoming queries, using the
specified files.
    """
    my_server = simple_data_server(
        host, port,
        getter, files,
        query_key=query_key, reply_key=reply_key)
    my_server.start()

def get_response(query, host, port, tcp=False,
                 query_key=None, reply_key=None,
                 protocol_version=0,
                 encryption_version=2, # hybrid encryption with base64 encoding (see global variables `encryptors' and `decryptors')
                 authentication_version=0,
                 application_version=0):
    """Send your query to the server, and return its result.

This is a client suitable for the simple_data_server class.
    """
    query = query + "\n"
    if query_key:
        query = encrypt(query, query_key, encryption_version)
    else:
        query = bytes(query, 'utf-8')
        # this tells the server to treat the data as plaintext
        encryption_version = 0
    query = (bytes((protocol_version,
                    encryption_version,
                    authentication_version,
                    application_version))
             + query)
    if tcp:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((host, int(port)))
            sock.sendall(query)
            received = sock.recv(1024)
        finally:
            sock.close()
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(query, (host, int(port)))
        received = sock.recv(1024)
    (protocol_version, encryption_version,
     authentication_version, application_version) = received[:4]
    return decrypt(received[4:], reply_key, encryption_version)

def read_key(filename, passphrase=None):
    """Wrap importKey with file opening, for easy use in comprehensions."""
    with open(filename) as reply_stream:
        return RSA.importKey(reply_stream.read(),
                             passphrase=passphrase)

def client_server_add_arguments(parser, port=9999, with_short=False):
    """Add the argparse arguments for the server.
The optional argument port specifies the default port to use.
If the argument with_short is given and non-False, add short
options too; otherwise make them something less likely
to clash with non-demo applications."""
    parser.add_argument('--host', '-H' if with_short else '-SH',
                        default="127.0.0.1",
                        help="""The server to handle the query.""")
    parser.add_argument('--port', '-P' if with_short else '-SP',
                        default=port,
                        help="""The port on which to send the query.""")
    parser.add_argument("--tcp", "-t" if with_short else '-St',
                        action='store_true',
                        help="""Use a TCP connection to communicate with the server.
                        Otherwise, UDP will be used.
                        Only applies when running as a client; the server does both.""")
    parser.add_argument("--query-key", "-q" if with_short else '-Sqk',
                        help="""The key files for decrypting the queries.
                        These are public keys, so may be visible to all users.""")
    parser.add_argument("--reply-key", "-r" if with_short else '-Srk',
                        default=None,
                        help="""The key file for encrypting the replies.
                        This is a private key, so should be kept unreadable
                        to everyone except the server user.
                        If this is not given, replies are sent in plaintext.""")

def check_private_key_privacy(args):
    private_key = args.query_key if args.server else args.reply_key
    if private_key:
        key_perms = os.stat(private_key).st_mode
        if key_perms & (stat.S_IROTH
                        | stat.S_IRGRP
                        | stat.S_IWOTH
                        | stat.S_IWGRP):
            print("Key file", private_key, "is open to misuse.")
            sys.exit(1)

def read_keys_from_files(args, query_passphrase, reply_passphrase):
    return ((read_key(args.query_key, query_passphrase)
             if args.query_key and len(args.query_key) > 0
             else None),
            (read_key(args.reply_key, reply_passphrase)
             if args.reply_key and len(args.reply_key) > 0
             else None))

def client_server_main(getter, files, verbose=False):
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

You may be able to use this directly as the main function of your
program, but you will probably have extra pieces you need, so some
parts of it have been split out for you to call from your own main.

See the documentation of the simple_data_server class, or the
accompanying README.md, for a less terse description.

    """
    parser=argparse.ArgumentParser()
    parser.add_argument("--gen-key",
                        help="""Generate a key in the specified file, and its
                        associated public key in that name + '.pub'.
                        Uses the 'query_passphrase' from the .env file unless
                        the '--server' argument is also given, in which case it
                        uses the 'reply_passphrase'.
                        No other action is done.""")
    parser.add_argument('--server', '-S',
                        action='store_true',
                        help="""Run as the server.
                        Otherwise, it will run as a client.
                        If given with --gen-key, make it generate a key using the server passphrase.""")
    parser.add_argument('data', nargs='*', action='append',
                        help="""The data to send to the server.""")
    client_server_add_arguments(parser)
    args=parser.parse_args()
    query_passphrase = decouple.config('query_passphrase')
    reply_passphrase = decouple.config('reply_passphrase')
    if args.gen_key:
        passphrase = reply_passphrase if args.server else query_passphrase
        with open(args.gen_key, 'w') as keystream:
            with open(args.gen_key + ".pub", 'w') as pubkeystream:
                key = RSA.generate(1024, Random.new().read)
                keystream.write(str(key.exportKey(passphrase=passphrase),
                                    'utf-8'))
                pubkeystream.write(
                    str(key.publickey().exportKey(passphrase=passphrase),
                        'utf-8'))
        return None
    else:
        check_private_key_privacy(args)
        query_key, reply_key = read_keys_from_files(args,
                                                    query_passphrase,
                                                    reply_passphrase)

        if args.server:
            run_servers(args.host, int(args.port),
                        getter=getter,
                        files=files,
                        query_key=query_key,
                        reply_key=reply_key)
            return None
        else:
            text = " ".join(args.data[0])

            received = get_response(
                text,
                args.host, args.port, args.tcp,
                encryption_version=(2 if query_key and reply_key else 0),
                query_key=query_key,
                reply_key=reply_key)

            if verbose:
                print("Sent:     {}".format(text))
                print("Received: {}".format(received))
            return received

#### Example ####

demo_filename = "/var/local/demo/demo-main.csv"

def demo_getter(in_string, files_data):
    """A simple query program that uses the first column in the CSV file
as the key, and returns the whole row."""
    return str(files_data[os.path.basename(demo_filename)]
               .get(in_string.strip().split()[0],
                    ["Unknown"]))

def main():
    client_server_main(demo_getter,
                       {demo_filename: 0},
                       verbose=True)

if __name__ == "__main__":
    main()
