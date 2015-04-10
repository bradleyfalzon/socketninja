Hi Brad

An alternative to whatever you're trying to do is this.


libsn/
    tcpraw/
        # tcpraw package will be all the code to handle a tcp connection across a raw socket
        # this includes retransmissions, syn generation - ack replies etc
        #
        # The key point to tcpraw is prehooks, each function will check if there's a prehook.
        # If there is a prehook, execute it and check the return status - if the return status is false
        # do not execute the remaining function - this allows someone to override basic functionality
        # like ack reponses.
        #
        # Alternatively, is this something we should do with interfaces or inheritance, so someone could
        # define a prehook, and the normal function could check if it exists (and if so runs it). Also
        # the caller could completely just override a function. No worrying about return status.
        main.go - entry point for package
        blah.go - various

