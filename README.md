A server for applying a user-supplied function to data from clients
===================================================================

This code makes it easy to write simple clients and servers for
retrieving information from server-side files, with further assistance
if those files are CSV formatted.  It defines a client and server pair
with a given port number, allowing use of both TCP and UDP, and reads
the data files for you, re-reading them if they have been modified
since the previous query.

For now, it has no provision for writing modified data back to the
files, and it has encryption but only implicit authentication, and
there is no logging.  These may all change in the future.

As I couldn't find all the information I needed for writing a very
simple client-server system all in one place, I've tried to make this
code suitable for use as an example or as a base for your own code.

However, it's years since I previously did any network programming,
and this is my first venture into encryption and decryption, so until
I get some feedback from people with more experience of these areas,
it might not be very good example code.

How to use it
=============

The main entry points are a function to run TCP and UDP servers,
applying a function you supply and with data files you specify:

    run_servers(host, port, getter, files)

and a function for sending a query and getting a response:

    get_response(query, host, port, tcp=False)

and a main-like function:

    client_server_main(getter, files)

which sets up argparse for the main options and then runs as either a
client or a server using the functions above.

The data definition
-------------------

The argument mentioned as `files` above is a dictionary binding
filenames to descriptions of how to read the files.  Each description
may be:

 * a function taking two arguments, the name of a file to read and a
   key (the key is not used); the function should return the data as
   its result, in whatever form your query function wants

 * a tuple of a function and a key; the function is called with the
   filename and the key; the function should return the data as
   its result, in whatever form your query function wants

 * a string, which is passed to a function (provided by this package)
   that uses `csv.DictReader` to parse the file, and constructs a
   dictionary binding the field of each row named by that string, to
   the row as a whole

 * an integer, which is passed to a function (provided by this
   package) that uses `csv.reader` to parse the file, and constructs a
   dictionary binding the column of each row indexed by that integer,
   to the row as a whole

The user function
-----------------

The user-supplied function is called with two arguments:

 * a string containing the query

 * a dictionary binding the basenames of the filenames to the results
   of the readers described above.  It should return the string which
   is to be sent back to the client.

Optional encryption
-------------------

For encryption, there are some further arguments you can supply to
`run_servers`:

    run_servers(host, port, getter, files,
                query_keys=None,
                shibboleth=None, shibboleth_group=None,
                reply_key=None)

The `query_keys` argument should be either `None`, or a list of
decryption keys, in which case they will all be tried to see if they
can make sense of the input.  Making sense of the input is defined by
the `shibboleth` argument, which is a regexp to try on the result of
the decryption.  When a decryption result matches the regexp, if a
`shibboleth_group` argument is given, that is used as the match group
to extract the data to give to the query function; if no
`shibboleth_group` is given, the entire decryption result is used.

If a `reply_key` is given, it is used to encrypt the reply.

The `get_response` function likewise has some further arguments for
encryption:

    get_response(query, host, port, tcp=False,
                 query_keys=None, reply_key=None)

Examples
--------

A very simple example is provided at the end of the source file, that
looks things up in a CSV file `/var/local/demo/demo-main.csv`, using
the first column as a key.

The program I started writing it as a wrapper for is for looking up
where I have stored things at home:
https://github.com/hillwithsmallfields/qs/blob/master/inventories/storage.py

Sometime I'll interface the two, and present it as another example
here.

When I get round to learning to write Android apps, the idea is to
have a phone or tablet use this to ask my home server where something
is, and, if I've added a writeback facility, to record where I've put
things.

Development
===========

I wrote this partly as an exercise for reminding myself about socket
programming.  I'll use it as an example for some future learning
projects:

 * Python's logging facilities
