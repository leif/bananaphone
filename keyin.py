#!/usr/bin/env python

import time
from getch import getch
from cocotools import *
from Queue import Empty

@coroutine
def hd ( target ):
    while True:
        c = yield
        target.send( "%s %s %s\n" % (hex(ord(c)),bin(ord(c)),c) )

@coroutine
def getc( target ):
    while True:
        c = getch()
        if c in '\x03\x04':
            target.send('')
            break
        target.send( c )
    yield

def poster ( maxLen, idleTime ):
    @coThread.withQueueAccess
    def _poster ( queue, target ):
        last = time.time()
        buf = []
        while True:
            sendNow=False
            try:
                value = queue.get( block = False )
            except Empty:
                pass
            else:
                if value == '':
                    break
                if '\x20' <= value <= '\x7e':
                    target.send( value )
                    buf.append(value)
                elif value == '\r':
                    target.send('\r\n')
                    buf.append('\n')
                last = time.time()
            if (buf[-2:] == ['\n']*2):
                sendNow = True
            elif (len(buf) >= maxLen) or (len(buf) and ((time.time() - last) > idleTime)):
                sendNow = True
            if ( sendNow ):
                msg = "".join(buf).strip()
                if len(msg):
                    print "\r\nmsg: %r\r" % ( msg, )
                buf = []
    return _poster

#getc | cmap(lambda s: s.replace('\r','\n')) > sys.stdout.write
getc |poster( 140, 1 ) > sys.stdout.write


