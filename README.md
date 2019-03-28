A server for applying a user-supplied function to data from clients
===================================================================

This code makes it easy to write simple clients and servers for
retrieving information from server-side files, with further assistance
if those files are CSV formatted.  It defines a client and server pair
with a given port number, allowing use of both TCP and UDP, and reads
the data files for you, re-reading them if they have been modified
since the previous query.

For now, it has no provision for writing modified data back to the
files, and it has no authentication (I suspect that adding that will
require adding an HTTPS server), and there is no logging.  These may
all change in the future.

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

The user-supplied function is called with two arguments, a string
containing the query, and a dictionary binding the basenames of the
filenames to the results of the readers described above.  It should
return the string which is to be sent back to the client.

Example
-------

A very simple example is provided at the end of the source file, that
looks things up in a CSV file `/var/local/demo/demo-main.csv`, using
the first column as a key.

Development
===========

I wrote this partly as an exercise for reminding myself about socket
programming.  I'll use it as an example for some future learning
projects:

 * Encrytion and Authentication (being worked on in this branch)

 * Python's logging facilities
