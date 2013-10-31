#!/usr/bin/env python

"""
concurrent composable coroutines
"""

__author__    = "Leif Ryge <leif@synthesize.us>"
__copyright__ = "No Rights Reserved, Uncopyright 2012"
__license__   = "WTFPL"
 
import os
import sys
import time
import Queue
import threading
import multiprocessing

class composable ( object ):
    """function composition decorator
    Decorate functions with this so you can write
        a | b | c | d
    instead of
        lambda *args, **kwargs: a(b(c(d(*args,**kwargs))))
    """

    def __init__ ( self, fn ):
        self._fn = fn

    def __call__ ( self, *args, **kwargs ):
        return self._fn( *args, **kwargs )

    def __or__ ( self, other ):
        @type(self)
        def composed ( *args, **kwargs ):
            return self._fn( other( *args, **kwargs ) )
        return composed

class coroutine ( composable ):
    """composable coroutine decorator
    >>> def ngram ( n ):
    ...    @coroutine
    ...    def _ngram ( target ):
    ...        prev = tuple( [ (yield) for i in range(n) ] )
    ...        while True:
    ...            target.send( prev )
    ...            prev = prev[ 1: ] + ( (yield), )
    ...    return _ngram
    >>> debugPipeline = cmap(str) | cmap(lambda s:"debug: "+s) > sys.stdout.write
    >>> a = []
    >>> co = cmap( lambda x:x*2 ) | ngram( 3 ) | tee( debugPipeline ) > a.append
    >>> co.send( 0 )
    >>> co.send( 1 )
    >>> co.send( 2 )
    debug: (0, 2, 4)
    >>> co.send( 3 )
    debug: (2, 4, 6)
    >>> a
    [(0, 2, 4), (2, 4, 6)]
    >>> co.send( 4 )
    debug: (4, 6, 8)
    """
    def __init__ ( self, fn ):
        "Wrap a coroutine in the starter function"
        if fn.__name__ == 'composed':
            # don't wrap the 'composed' functions made by composable
            composable.__init__( self, fn )
        else:
            def _coroutine ( *args, **kwargs ):
                g = fn( *args, **kwargs )
                g.next() # start the coroutine
                return g
            composable.__init__( self, _coroutine )

    def __gt__ ( self, fn ):
        "Initialize coroutine with a callable as its sink"
        @coroutine
        def sink():
            while True:
                fn( (yield) )
        return self( sink() )

    def __lt__ ( self, iterable ):
        "Turn coroutine into a normal generator, pulling from another iterable"
        results = []
        target = self > results.append
        for value in iterable:
            target.send( value )
            for result in results:
                yield result
            results[:] = []
        target.close()


class QueueCoroutine ( coroutine ):
    """Connect to a coroutine via a Queue
    This allows a coroutine to run in another process or thread and receive
    data via a Queue. It will execute its target (including anything it is
    composed with) in the same other process.  If it is turned into a generator
    using the '<' operator, its output can be received in the first process (by
    way of another Queue).
    
    If you'd like your coroutine in the other process to be able to do something
    while waiting for data, you can access the queue directly instead of
    yielding for input by decorating your function with
    co{Thread,Process}.withQueueAccess. In this case, your function must take
    two arguments (queue, target) and can then poll the queue with non-blocking
    or blocking-with-timeout calls to get().

    Note: the below doctest is somewhat fragile and will probably only pass if
    your computer wins/loses a race condition the same way as mine usually does.

    >>> @coProcess.withQueueAccess # also works with coThread
    ... def countdown( queue, target ):
    ...   for i in range(5, 0,-1):
    ...     try:
    ...       value = queue.get( block=False )
    ...     except Queue.Empty:
    ...       value = 'Sleeping'
    ...     target.send( '%s: %s' % (i, value) )
    ...     time.sleep(0.01)
    >>> queue = type( countdown ).Queue( )
    >>> p = cmap( lambda x:x*3 ) | countdown > queue.put
    >>> p.send( 1 )
    >>> p.send( 2 )
    >>> time.sleep(0.035)
    >>> p.send( 3 )
    >>> queue.get()
    '5: Sleeping'
    >>> queue.get()
    '4: 3'
    >>> queue.get()
    '3: 6'
    >>> queue.get()
    '2: Sleeping'
    >>> queue.get()
    '1: 9'
    """

    Queue           = NotImplemented 
    ThreadOrProcess = NotImplemented

    def __init__ ( self, fn, withQueueAccess = False ):
        if fn.__name__ == 'composed':
            composable.__init__( self, fn )
        else:
            if withQueueAccess:
                _queueReader = fn
            else:
                def _queueReader( queue, nextTarget ):
                    target = coroutine( fn )( nextTarget )
                    while True:
                        value = queue.get()
                        if value == '':
                            target.close()
                            break
                        target.send( value )
            def _queueWriter ( target ):
                queue = self.Queue( 10 )
                p = self.ThreadOrProcess( target=_queueReader, args=(queue, target) )
                p.start()
                while True:
                    try:
                        queue.put( (yield) )
                    except GeneratorExit:
                        queue.put( '' )
                        break
            coroutine.__init__( self, _queueWriter )

    @classmethod
    def withQueueAccess( cls, fn ):
        return cls( fn, withQueueAccess = True )

    def __lt__ ( self, iterable ):
        """
        Turn concurrent coroutine into a normal generator, pulling from another
        iterable. The sending and receiving iterables operate in the calling
        process; the concurrent coroutine (including anything after it in a
        pipeline) is not.
        """
        results = self.Queue( 10 )
        target = self > results.put
        for value in iterable:
            target.send( value )
            while True:
                try:
                    yield results.get( block=False )
                except Queue.Empty:
                    break
        target.close()

class coProcess ( QueueCoroutine ):
    "QueueCoroutine using multiprocessing"
    Queue           = staticmethod( multiprocessing.Queue   )
    ThreadOrProcess = staticmethod( multiprocessing.Process )

class coThread ( QueueCoroutine ):
    "QueueCoroutine using threading"
    Queue           = staticmethod( Queue.Queue      )
    ThreadOrProcess = staticmethod( threading.Thread )

def tee ( targetOne ):
    @coroutine
    def _tee ( targetTwo ):
        while True:
            value = yield
            targetOne.send( value )
            targetTwo.send( value )
    return _tee


def cfilter ( fn ):
    @coroutine
    def _cfilter ( target ):
        while True:
            value = yield
            if fn( value ):
                target.send( value )
    return _cfilter

def cmap ( fn ):
    @coroutine
    def _cmap( target ):
        while True:
            target.send( fn( (yield) ) )
    return _cmap

def cstarmap ( fn ):
    @coroutine
    def _cstarmap( target ):
        while True:
            target.send( fn( * (yield) ) )
    return _cstarmap

def cmapstar ( fn ):
    @coroutine
    def _cmapstar( target ):
        while True:
            for value in fn( (yield) ):
                target.send( value )
    return _cmapstar

def cgenerator ( coroutine ):
    "Transform a coroutine (send()-based) into a generator (next()-based)"
    def _generator ( iterable ):
        results = []
        co = coroutine( fnSink( results.append ) )
        for value in iterable:
            co.send( value )
            for result in results:
                yield result
            results[:] = []
    return _generator

@coroutine
def cat ( target ):
    "Identity"
    while True:
        target.send( (yield) )

def pv ( interval = 1, report = cat > sys.stderr.write ):
    "Monitor the throughput of data through a pipeline"
    @coroutine
    def _pv ( target ):
        count = 0
        last = time.time()
        while True:
            value = yield
            target.send( value )
            count += len( value )
            now = time.time()
            delta = now - last
            if delta > interval:
                report.send( "\x5d\x0d[%.2fkB/s]" % ( count / 1024.0 / delta , ) )
                last = now
                count = 0
    return _pv

@coroutine
def cdebug( target ):
    "print all data sent and exceptions thrown"
    while True:
        try:
            value = yield
            print "Sending ", value
        except Exception, ex:
            print "Throwing ", ex
            target.throw( ex )
        else:
            target.send( value )

if __name__ == "__main__":
    import doctest
    doctest.testmod()

# Simple composition function; maybe I should use this instead of all the
# operator overloading jazz.
compose = lambda fns: lambda a: reduce( lambda n,f: f(n), fs, a )

# my original version of composable coroutines:
#def composable ( fn ):
#    """Function composition decorator
#    Decorate functions with this so you can write
#        a | b | c | d
#    instead of
#        lambda *args, **kwargs: a(b(c(d(*args,**kwargs))))
#    """
#    class _composable ( object ):
#        def __call__ ( self, *args, **kwargs ):
#            return fn( *args, **kwargs )
#        def __or__ ( self, target ):
#            @composable
#            def composed ( *args, **kwargs ):
#                return fn( target( *args, **kwargs ) )
#            return composed
#    return _composable()
#def coroutine( fn ):
#    def _coroutine ( *args, **kwargs ):
#        g = fn( *args, **kwargs )
#        g.next()
#        return g
#    return _coroutine
# coco = composable( composable ) | coroutine

