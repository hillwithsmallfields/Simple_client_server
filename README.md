A wrapper for Python's socketserver
===================================

Having written some command-line python programs that look stuff up in
CSV files and do a bit of application-specific processing, I didn't
want to have them re-read the same data for each lookup (although
actually it's pretty quick, on the scale I'm working at, i.e. not big
enough to feel the need to go over to a proper database system).  So I
learnt how to use Python's socketserver class, and a few related
things, then condensed it down to this.

Status
------

Not really quite ready (it works, but not the way I want it to); I
want to call self.service.get_result, but what is passed when
MyTCPHandler/MyUDPHandler is specified is the class object, not an
instance, so the service can't be passed in for creating it.
