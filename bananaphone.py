#!/usr/bin/env python
# -*- coding: utf-8 -*-
r"""
bananaphone.py - stream encoding toolkit

The codecs implemented here are intended to eventually be usable as Tor
pluggable transports, but this does not yet implement the pluggable transport
specficiation. Currently these encoders can be used as shell pipelines and as a
TCP proxy.

=== Reverse Hash Encoding ===

Reverse hash encoding is a steganographic encoding scheme which transforms a
stream of binary data into a stream of tokens (eg, something resembling natural
language text) such that the stream can be decoded by concatenating the hashes
of the tokens.

TLDR: SSH over Markov chains

This encoder is given a word size (number of bits), a tokenization function (eg,
split text on whitespace), a hash function (eg, sha1), a corpus, and a modeling
function (eg, a markov model, or a weighted random model). The range of the
hash function is truncated to the word size. The model is built by tokenizing
the corpus and hashing each token with the truncated hash function. For the
model to be usable, there must be enough tokens to cover the entire hash space
(2^(word size) unique hashes). After the model is built, the input data bytes
are scaled up or down to the word size (eg, scaling [255, 18] from 8-bit bytes
to 4-bit words produces [15, 15, 1, 2]) and finally each scaled input word is
encoded by asking the model for a token which hashes to that word. (The
encoder's model can be thought of as a probabilistic reverse hash function.)

DISCLAIMER: This was written as a fun experimental proof-of-concept hack, and
in its present form it is TRIVIALLY DETECTABLE since there is no encryption
used. (When you ssh over it, an observer only needs to guess your tokenization
function, hash function and word size to see that you are using ssh.)

USAGE NOTES:
The tokenization function needs to produce tokens which will always re-tokenize
the same way after being concatenated with each other in any order. So, for
instance, a "split on whitespace" tokenizer actually needs to append a
whitespace character to each token. The included "words" tokenizer replaces
newlines with spaces; "words2" does not, and "words3" does sometimes. The other
included tokenizers, "lines", "bytes", and "asciiPrintableBytes" should be
self-explanatory.

For streaming operation, the word size needs to be a factor or multiple of 8.
(Otherwise, bytes will frequently not be deliverable until after the subsequent
byte has been sent, which breaks most streaming applications). Implementing the
above-mentioned layer of timing cover would obviate this limitation. Also, when
the word size is not a multiple or factor of 8, there will sometimes be 1 or 2
null bytes added to the end of the message (due to ambiguity when converting
the last word back to 8 bits).

The markov encoder supports two optional arguments: the order of the model
(number of previous tokens which constitute a previous state, default is 1),
and --abridged which will remove all states from the model which do not lead to
complete hash spaces. If --abridged is not used, the markov encoder will
sometimes have no matching next token and will need to fall back to using the
random model. If -v is specified prior to the command, the rate of model
adherence is written to stderr periodically. With a 3MB corpus of about a half
million words (~50000 unique), at 2 bits per word (as per the SSH example
below) the unabridged model is adhered to about 90% of the time.

EXAMPLE USAGE:
encode "Hello\n" at 13 bits per word, using a dictionary and random picker:
    echo Hello | ./bananaphone.py pipeline 'rh_encoder("words,sha1,13", "random", "/usr/share/dict/words")'

decode "Hello\n" from 13-bit words:
    echo "discombobulate aspens brawler Gödel's" | ./bananaphone.py pipeline 'rh_decoder("words,sha1,13")'

decode "Hello\n" from 13-bit words using the composable coroutine API:
    >>> "".join( str("discombobulate aspens brawler Gödel's\n") > rh_decoder("words,sha1,13") )
    'Hello\n'

start a proxy listener for $sshhost, using markov encoder with 2 bits per word:
    socat TCP4-LISTEN:1234,fork EXEC:'bash -c "./bananaphone.py\\ pipeline\\ rh_decoder(words,sha1,2)|socat\\ TCP4\:'$sshhost'\:22\\ -|./bananaphone.py\\ -v\\ rh_encoder\\ words,sha1,2\\ markov\\ corpus.txt"' # FIXME: shell quoting is broken in this example usage after moving to the pipeline model

same as above, but using bananaphone.tcp_proxy instead of socat as the server:
    python -m bananaphone tcp_proxy rh_server words,sha1,2 markov corpus.txt

connect to the ssh host through the $proxyhost:
    ssh user@host -oProxyCommand="./bananaphone.py pipeline 'rh_encoder((words,sha1,2),\"markov\",\"corpus.txt\")'|socat TCP4:$proxyhost:1234 -|./bananaphone.py pipeline 'rh_decoder((words,sha1,2))'"

=== Hammertime encoding ===

This is a chaff layer intended to impede passive timing analysis. It should be
layered underneath a stream cipher (not yet implemented here).

Threat models:
Alice establishes a TCP connection to Bob via the Tor network.

Scenario #1: Eve sits at Alice and Bob's ISPs and observes all trafffic.
Scenario #2: Same as #1, but Eve also observes the Tor bridge Alice uses.

Using Hammertime (with a stream cipher outside of it) should prevent Eve from
being able to confirm that Alice is the person making a TCP connection to Bob
in scenario #1. Alice is only protected in scenario #2 if there are many
simultaneous users of hammertime encoding on the same bridge. (Eve can
be sure that Bob's TCP peer is one of them, but not which one.)

Threat models NOT addressed:
* Eve controls the entrance node (bridge)
* Eve is able to actively delay or drop packets somewhere between Alice and Bob

Hammertime does not protect against these threat models, and it is the author's
opinion that it is probably not possible to protect against them while
maintaining low enough latency to estabish TCP connections.

TODO:
* add stream cipher
** hammertime needs one to be at all useful. TLS would be fine.
** RH encoding needs an indistinguishable one to provide more than obfuscation.
* document hammertime usage
* implement Tor pluggable transport spec
"""

__author__    = "Leif Ryge <leif@synthesize.us>"
__copyright__ = "No Rights Reserved, Uncopyright 2012"

import os, sys, time, readline
from random      import choice, randrange
from hashlib     import md5, sha1, sha224, sha256, sha384, sha512
from itertools   import islice, imap
from collections import deque
from cocotools   import cmap, cfilter, coroutine, composable, cdebug, cmapstar, tee, coThreadWithQueueAccess, pv

HASHES  = [ md5, sha1, sha224, sha256, sha384, sha512 ]
GLOBALS = globals()

global verbose
verbose = False

def debug ( message ):
    if verbose:
        sys.stderr.write( "%s\n" % (message,) )
    return message

def formatGlobalNames ( objectList ):
    return "<%s>" % ( "|".join( k for k,v in GLOBALS.items() if v in objectList ), )

def register( registry, name ):
    def decorator( function ):
        registry[ name ] = function
        return function
    return decorator

def appendTo ( objectList ):
    def decorator( function ):
        objectList.append( function )
        return function
    return decorator

def mergeDicts ( *dicts ):
    return reduce( lambda a, b: a.update(b) or a, dicts, {} )


def changeWordSize ( inSize, outSize ):
    """
    >>> list( changeWordSize( 8, 1 ) < [255, 18] )
    [1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0]
    >>> list( changeWordSize( 8, 4 ) < [255, 18] )
    [15, 15, 1, 2]
    >>> list( changeWordSize( 4, 8 ) < [15, 15, 1, 2] )
    [255, 18]

    NOTE: this will sometimes add trailing null words when inSize is not a
    factor or multiple of outSize:
    >>> list( changeWordSize( 8, 5 ) < [255, 18] )
    [31, 28, 9, 0]
    >>> list( changeWordSize( 5, 8 ) < [31, 28, 9, 0] )
    [255, 18]
    """
    @coroutine
    def _changeWordSize ( target ):
        assert inSize  > 0
        assert outSize > 0
        bits  = 0
        value = 0
        while True:
            try:
                word = yield
            except GeneratorExit:
                break
            assert type(word) in (int, long), "words must be int or long, got %s" % ( type( word ), )
            assert 0 <= word < 2 ** inSize  , "words must be in range 0 to 2**%s-1, got %s" % ( inSize, word )
            value  = value << inSize
            value += word
            bits  += inSize
            while outSize <= bits:
                bits    -= outSize
                newWord  = value >> bits
                value   -= newWord << bits
                target.send( newWord )
        target.send( value << ( outSize - bits ) )
    return _changeWordSize


def buildWeightedRandomModel ( corpusTokens, hash ):
    model = {}
    for token in corpusTokens:
        model.setdefault( hash( token ), [] ).append( token )
    return model


def ngram ( n ):
    """
    >>> list( ngram(2) < range(5) )
    [(0, 1), (1, 2), (2, 3), (3, 4)]
    """
    @coroutine
    def _ngram ( target ):
        prev = tuple( [ (yield) for i in range(n) ] )
        while True:
            target.send( prev )
            prev = prev[ 1: ] + ( (yield), )
    return _ngram

def ngramPlusOne ( n ):
    """
    >>> list( range(5) > ngramPlusOne( 1 ) )
    [((0,), 1), ((1,), 2), ((2,), 3), ((3,), 4)]
    >>> list( range(5) > ngramPlusOne( 2 ) )
    [((0, 1), 2), ((1, 2), 3), ((2, 3), 4)]
    """
    return ngram( n + 1 ) | cmap( lambda gram: ( gram[ :-1 ], gram[ -1 ] ) )

def buildMarkovModel ( statePairs ):
    model = {}
    for prev, next in statePairs:
        if prev not in model:
            model[ prev ] = {}
        if next not in model[ prev ]:
            model[ prev ][ next ] = 0
        model[ prev ][ next ] +=  1
    return model

def buildHashPartitionedMarkovModel ( tokens, hash, order ):
    markovModel = buildMarkovModel( ngramPlusOne( order ) < tokens )
    partitionedModel = {}
    for prev in markovModel:
        partitionedModel[ prev ] = {}
        for next, nextCount in markovModel[ prev ].items():
            encodedValue = hash( next )
            if encodedValue not in partitionedModel[ prev ]:
                partitionedModel[ prev ][ encodedValue ] = {}
            partitionedModel[ prev ][ encodedValue ][ next ] = nextCount
    return partitionedModel


def getPercentFull ( space, bits ):
    totalHashes = float( 2 ** bits )
    percentFull = len( space ) / totalHashes * 100
    return percentFull


def removeIncompleteSpaces ( model, bits ):

    """
    This takes a hash-partitioned model and removes all of the states which do
    not lead to enough next states to cover the entire hash space.
    """

    abridgedModel    = dict( (prev, space) for prev, space in model.items()
                             if getPercentFull( space, bits ) == 100 )
    totalSpaces      = len( model )
    completeSpaces   = len( abridgedModel )
    incompleteSpaces = totalSpaces - completeSpaces

    debug( "%s states - %s leading to complete spaces = %s to drop"
                % (totalSpaces, completeSpaces, incompleteSpaces) )

    assert completeSpaces > 1, "not enough tokens for %s bit hashing" % ( bits, )

    if incompleteSpaces:
        model = dict(
                (   prev,
                    dict(
                          ( value,
                            dict(   (word, count) for word, count in words.items()
                                    if prev[ 1: ] + (word,) in abridgedModel
                                )
                          ) for value, words in space.items()
                        )
                ) for prev, space in abridgedModel.items()
               )
        for prev in model:
            for value in model[ prev ].keys():
                if len( model[ prev ][ value ] ) == 0:
                    del model[ prev ][ value ]
        model = removeIncompleteSpaces( model, bits )

    return model

@appendTo(HASHES)
class phash ( object ):
    def __init__(self, bytes):
        self._val = sum( (ord(byte) | 0x20) - 96 for byte in bytes )
    def hexdigest(self):
        return hex( self._val )

def truncateHash ( hash, bits ):

    def truncatedHash ( input ):
        return int( hash( input ).hexdigest(), 16 ) % ( 2 ** bits )
    
    return truncatedHash


def parseEncodingSpec ( encodingSpec ):

    if type( encodingSpec ) is tuple:
        return encodingSpec
    
    tokenize, hash, bits = encodingSpec.split(",", 3)

    tokenize = GLOBALS.get( tokenize )
    hash     = GLOBALS.get( hash )
    bits     = int( bits )

    assert tokenize in TOKENIZERS, "tokenizer must be one of %s" % ( formatGlobalNames( TOKENIZERS ), )
    assert hash     in HASHES, "hash function must be one of %s" % ( formatGlobalNames( HASHES     ), )
    assert bits > 0

    return ( tokenize, hash, bits )


def readTextFile ( filename ):
    return "".join( file( filename ) ).replace("\r", "")



TOKENIZERS = []

@appendTo(TOKENIZERS)
@coroutine
def toBytes ( target ):
    while True:
        for byte in (yield):
            target.send(byte)

asciiPrintableBytes = toBytes | cfilter( lambda b: 0x20 <= ord(b) <= 0x7e)
appendTo(TOKENIZERS)( asciiPrintableBytes )

def streamTokenizer ( stopBytes ):
    "Return a tokenizer coroutine which accumulates bytes until it sees a byte in stopBytes"
    @coroutine
    def tokenizer ( target ):
        value = []
        while True:
            byte = yield
            value.append( byte )
            if byte in stopBytes:
                target.send( "".join( value ) )
                value = []
    return tokenizer


words = streamTokenizer( " \n" ) \
        | cfilter( lambda token: token not in ( " ", "\n" ) ) \
        | cmap( lambda token: token.strip() + ' ' )
appendTo(TOKENIZERS)( words )


lines  = appendTo(TOKENIZERS)( streamTokenizer( "\n" ) )
words2 = appendTo(TOKENIZERS)( streamTokenizer( " \n.,;?!" ) )
words3 = appendTo(TOKENIZERS)( streamTokenizer( " \n.,;?!" )
                               | cmap( lambda word: word[:-1]+' ' if word.endswith("\n") and not word == "\n" else word ) )


MODELS = []

@appendTo(MODELS)
def markov ( tokenize, hash, bits, corpusFilename, order=1, abridged=None ):
    truncatedHash = truncateHash( hash, bits )
    corpusTokens  = list( tokenize < readTextFile( corpusFilename ) )
    order         = int( order )
    randomModel   = buildWeightedRandomModel( corpusTokens, truncatedHash )
    percentFull   = getPercentFull( randomModel, bits )
    assert percentFull == 100, "not enough tokens for %s-bit hashing (%s%% there)" % (bits, percentFull)
    model = buildHashPartitionedMarkovModel( corpusTokens, truncatedHash, order )
    debug( "%s states (%s tokens, %s unique, order=%s)" % ( len(model), len(corpusTokens), len( set(corpusTokens) ), order ) )

    if abridged == "--abridged":
        abridgedMarkovModel = removeIncompleteSpaces( model, bits )
        incompleteStates  = len(model) - len(abridgedMarkovModel)
        debug( "%s states which lead to incomplete hash spaces will not be used." % ( incompleteStates, ) )
        model = abridgedMarkovModel

    else:
        assert abridged == None, "Unrecognized option: %s" % ( abridged, )

    class stats:
        total   = 0
        adhered = order - 1

    prevList = [ None ]

    def encode ( value ):

        prevTuple = tuple( prevList )
        stats.total += 1

        if prevTuple in model and value in model[ prevTuple ] and len(model[ prevTuple ][ value ]):
            stats.adhered += 1
            choices = []
            for token, count in model[ prevTuple ][ value ].items():
                choices.extend( [token] * count )
        
        else:
            choices = randomModel[ value ]
        
        nextWord = choice( choices )

        if stats.total >= order:
            prevList.pop(0)

        prevList.append( nextWord )

        if not stats.total % 10**5:
            debug( "%s words encoded, %s%% adhering to model" % ( stats.total, (100.0* stats.adhered / stats.total ) ) )

        return nextWord

    return encode


@appendTo(MODELS)
def random ( tokenize, hash, bits, corpusFilename ):

    truncatedHash = truncateHash( hash, bits )
    corpusTokens  = list( tokenize < readTextFile( corpusFilename ) )
    model         = buildWeightedRandomModel( corpusTokens, truncatedHash )
    percentFull   = getPercentFull( model, bits )
    assert percentFull == 100, "not enough tokens for %s-bit hashing (%s%% there)" % (bits, percentFull)
    
    debug( "built weighted random model from %s tokens (%s unique)" % ( len(corpusTokens), len(set(corpusTokens)) ) )

    def encode( value ):
        return choice( model[ value ] )
    
    return encode


PIPELINES = []

@appendTo(PIPELINES)
def rh_decoder ( encodingSpec ):
    tokenize, hash, bits = parseEncodingSpec( encodingSpec )
    return toBytes | tokenize | cmap( truncateHash( hash, bits ) ) | changeWordSize( bits, 8 ) | cmap( chr )


@appendTo(PIPELINES)
def rh_encoder ( encodingSpec, modelName, *args ):

    tokenize, hash, bits = parseEncodingSpec( encodingSpec )

    model = GLOBALS.get( modelName )
    assert model in MODELS, "model must be one of %s, got %s" % ( formatGlobalNames( MODELS ), modelName )

    encode = model( tokenize, hash, bits, *args )
    
    return toBytes | cmap(ord) | changeWordSize(8, bits) | cmap(encode)

COMMANDS = {}

@register( COMMANDS, 'rh_encoder_permuter' )
def rh_encoder_permuter ( encodingSpec, modelName, corpusFilename, separator="0a", howMany=10**6, *args ):

    "Encode the same input many times."

    tokenize, hash, bits = parseEncodingSpec( encodingSpec )
    truncatedHash = truncateHash( hash, bits )
    separator = int( separator, 16 )

    model = GLOBALS.get( modelName )
    assert model in MODELS, "model must be one of %s, got %s" % ( formatGlobalNames( MODELS ), modelName )
    
    corpusTokens = list( tokenize < readTextFile( corpusFilename ) )

    encode = model( corpusTokens, truncatedHash, bits, *args )

    def process ( byteStream ):
        scaledWords = list( changeWordSize( map( ord, byteStream ), 8, bits ) )

        for i in range( int( howMany ) ):
            yield "".join( map(encode, scaledWords) ) + chr( separator )
    
    return process


@register( COMMANDS, 'rh_print_corpus_stats' )
def rh_print_corpus_stats ( encodingSpec, corpusFilename, order=1 ):

    tokenize, hash, bits = parseEncodingSpec( encodingSpec )
    corpusTokens = list( tokenize < readTextFile( corpusFilename ) )

    print "%s tokens, %s unique" % ( len(corpusTokens), len(set(corpusTokens)) )

    for bits in range(1, 25):
        truncatedHash = truncateHash( hash, bits )

        markovModel = buildHashPartitionedMarkovModel( corpusTokens, truncatedHash, int( order ) )

        try:
            abridgedModel = removeIncompleteSpaces( markovModel, bits )
            print "%s-bit %s: %s of %s states lead to full hash spaces" % ( bits, hash.__name__, len(abridgedModel), len(markovModel) )
        except AssertionError, e:
            print "maximum bits per word with abridged markov model: %s" % ( bits - 1 )
            for bits in range(bits, 25):
                truncatedHash = truncateHash( hash, bits )
                randomModel = buildWeightedRandomModel( corpusTokens, truncatedHash )
                if getPercentFull( randomModel, bits ) != 100:
                    print "maximum bits per word with random model: %s" % ( bits - 1 )
                    break
            break


from Queue import Empty

@coThreadWithQueueAccess
def hammertime_encoder ( queue, target ):
    """
    This adds chaff to a bytestream to impede passive timing analysis.
    """
    while True:
        finished = False
        data = []
        while True:
            try:
                value = queue.get( block=False )
                if value == '':
                    finished = True
                    break
                else:
                    data.append( value )
            except Empty:
                break
        dataLen = len( data )
        while dataLen > 0:
            frameSize = min( dataLen, 127 )
            target.send( chr( frameSize ) + "".join(data[:frameSize] ))
            data    = data[frameSize:]
            dataLen = len( data )
        else:
            target.send( chr(0xFF)+" "*127 )
        if finished:
            break

@coroutine
def hammertime_decoder ( target ):
    """
    This removes hammertime_encoder's chaff.
    """
    while True:
        frameHeader = ord( (yield) )
        frameType   = frameHeader & 128
        frameLength = frameHeader & 127
        debug ("Frame type %s length %s" % (frameType, frameLength))
        for i in range(0, frameLength):
            byte = yield
            if frameType == 0:
                target.send( byte )

def throttle ( bps ):
    "Throttles, but not quite how much you ask it to yet. FIXME"
    @coroutine
    def _throttle ( target ):
        last = time.time()
        while True:
            byte = yield
            target.send( byte )
            now = time.time()
            delta = now - last
            overspeedFactor = (1.0 / delta) / bps
            sleepTime = delta * (overspeedFactor - 1)
            if sleepTime > 0:
                debug( "Sleeping %s" % sleepTime )
                time.sleep( sleepTime )
            last = now
    return _throttle


@register( COMMANDS, 'httpd_chooser' )
def httpd_chooser ( encodingSpec   = 'words,sha1,12',
            corpusFilename = '/usr/share/dict/words',
            port           = 8000
            ):
    "Web UI for browsing available words which can encode a target value."

    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
    from urllib2        import urlparse

    serverAddress = ( '', int(port) )
    tokenize, hash, bits = parseEncodingSpec( encodingSpec )
    truncatedHash = truncateHash( hash, bits )
    corpusTokens  = list( tokenize < readTextFile( corpusFilename ) )
    debug( "Building model from %s tokens" % (len(corpusTokens),) )
    model         = buildWeightedRandomModel( corpusTokens, truncatedHash )
    percentFull   = getPercentFull( model, bits )
    assert percentFull == 100, "not enough tokens for %s-bit hashing (%s%% there)" % (bits, percentFull)
    class RequestHandler ( BaseHTTPRequestHandler ):
        def do_GET ( self ):
            self.send_response( 200 )
            self.send_header("Content-type", "text/html")
            self.end_headers()
            html = "<html><form><input name=input type=text><br>"
            data = urlparse.parse_qs( self.path[2:] ).get( 'input' )
            if data != None:
                for word in changeWordSize( map( ord, data[0] ), 8, bits ):
                    html += "<select>"
                    for token in sorted( set(model[ word ]), key=model[word].count, reverse=True ):
                        html += "<option>%s</option>" % ( token, )
                    html += "</select>"
            self.wfile.write( html + "\n" )
    debug( "Listening on port %s" % (port,) )
    HTTPServer( serverAddress, RequestHandler ).serve_forever()


@register( COMMANDS, 'tab_composer' )
def tab_composer ( 
            encodingSpec   = 'words,sha1,2',
            corpusFilename = 'corpus.txt',
            order          = 1,
            ):
    """readline tab completion through a markov model encoder"""
    inputData = sys.stdin.read()
    tokenize, hash, bits = parseEncodingSpec( encodingSpec )
    truncatedHash = truncateHash( hash, bits )
    debug( "Tokenizing corpus" )
    corpusTokens  = list( tokenize < readTextFile( corpusFilename ) )
    debug( "Building random model" )
    randomModel   = buildWeightedRandomModel( corpusTokens, truncatedHash )
    percentFull   = getPercentFull( randomModel, bits )
    assert percentFull == 100, "not enough tokens for %s-bit hashing (%s%% there)" % (bits, percentFull)
#    debug( "Ordering random model" )
#    randomModel   = dict( (state, sorted( set(values), key=values.count ) ) for state, values in randomModel.items() )
    debug( "Building markov model" )
    markovModel   = buildHashPartitionedMarkovModel( corpusTokens, truncatedHash, 1 )
#    markovModel   = removeIncompleteSpaces( markovModel, bits ) #BUG
    debug( "Scaling input data" )
    scaledData    = list( changeWordSize( map( ord, inputData ), 8, bits ) )

#    markovModel[()] = mergeDicts( *markovModel.values() )

    def completer ( text, stateN ):
        try:
            lineBuffer          = readline.get_line_buffer()
            lineBufferTokenized = list( tokenize( lineBuffer ) )
            lineBufferDecoded   = map( truncatedHash, lineBufferTokenized )
            decodedPosition     = len( lineBufferDecoded )

            if lineBufferDecoded == scaledData[ : decodedPosition ]:
                prevState = tuple( lineBufferTokenized[ (  0 - order ) : ] )

            elif text != "" and lineBufferDecoded[ : -1 ] == scaledData[ : decodedPosition - 1 ]:
                decodedPosition -= 1
                prevState = tuple( lineBufferTokenized[ ( -1 - order ) : ] )

            else:
                return None

            valueToEncode = scaledData[ decodedPosition ]

            stateDict = markovModel.get( prevState, {} ).get( valueToEncode, {} )
            states = sorted( stateDict.keys(), key=stateDict.get )

            if len( states ):
                states.append( "-----" )

            states.extend( randomModel[ valueToEncode ]  )

            states = filter( lambda s: s.startswith( text ), states )

            states = states[ :75 ]

            if stateN < len( states ):
                st = states[ stateN ]
                return st
        except Exception, e:
            print "Exception:", repr(e)
            raise

    readline.parse_and_bind( "tab: complete" )
    readline.set_completer( completer )
    sys.stdin = open( '/dev/tty', 'rb' )
    print "Ready to encode %s bytes." % ( len( inputData ), )
    print "Hit tab twice to see available words."
    raw_input( )


@register( COMMANDS, 'pipeline' )
def pipeline ( expression ):
    "connect stdin to stdout through a coroutine (evaluated from the given expression)"
    stdout = os.fdopen(sys.stdout.fileno(), 'w', 0) # do not want buffering
    stdin  = os.fdopen(sys.stdin .fileno(), 'r', 0) # do not want buffering
    coroutine = eval( expression )
    target = coroutine > stdout.write
    for byte in iter( lambda: stdin.read(1), '' ):
        target.send( byte )
    target.close()


CODECS = [] # A "codec" is a function that returns a pair of coroutines

@appendTo( CODECS )
def rh_client( encodingSpec, model, filename, *modelArgs ):
    return rh_encoder( encodingSpec, model, filename, *modelArgs ), \
           rh_decoder( encodingSpec )


@appendTo( CODECS )
def rh_server( encodingSpec, model, filename, *modelArgs ):
    return rh_decoder( encodingSpec ), \
           rh_encoder( encodingSpec, model, filename, *modelArgs )


@appendTo( CODECS )
def hammertime_client( ):
    return toBytes | hammertime_encoder, toBytes | hammertime_decoder


@appendTo( CODECS )
def hammertime_server( ):
    return toBytes| hammertime_decoder, toBytes | hammertime_encoder


@appendTo( CODECS )
def hammertime_rh_server ( encodingSpec="words,sha1,13", model="random", filename="/usr/share/dict/words", *modelArgs ):
    return hammertime_encoder | rh_encoder( encodingSpec, model, filename, *modelArgs ), \
           rh_decoder( encodingSpec ) | hammertime_decoder


class usage ( composable ):
    def __init__ ( self, fn ):
        def _command( *args, **kwargs ):
            try:
                return fn( *args, **kwargs )
            except TypeError:
                print fn.__doc__.format(globals=globals())
                raise
        composable.__init__( self, _command )


@register( COMMANDS, 'tcp_proxy' )
@usage
def tcp_proxy ( listenPort, destHostPort, codecName, *args ):
    """
    listenPort   - TCP port number to listen on
    destHostPort - host:port to connect to
    codecName    - name of encoder/decoder pair to use
    codecArgs    - codec parameters
    """

    from twisted.protocols import basic
    from twisted.internet  import reactor, protocol, defer

    def callFromThreadWrapper( fn ):
        def _callFromThreadWrapper( *args, **kwargs ):
            reactor.callFromThread( fn, *args, **kwargs )
        return _callFromThreadWrapper

    class ByteSinkProtocol ( protocol.Protocol ):

        def dataReceived(self, data):
            self.byteSink.send( data )

        def connectionLost(self, why):
            debug( "Connection lost." )
            self.loseRemoteConnection()


    class ProxyClient ( ByteSinkProtocol ):

        def connectionMade(self):
            debug( "Outbound connection established" )
            self.factory.proxyServer.clientConnectionMade( self )


    class ProxyClientFactory( protocol.ClientFactory ):

        protocol = ProxyClient

        def __init__(self, proxyServer ):
            self.proxyServer = proxyServer

        def clientConnectionFailed( self, connector, reason ):
            debug( "Connection failed: %s %s" % (connector, reason) )
            self.proxyServer.transport.loseConnection()


    class ProxyServer( ByteSinkProtocol ):

        def connectionMade(self):
            self.transport.pauseProducing()
            host, port = self.factory.destHostPort.split(':')
            debug( "Incoming connection established" )
            reactor.connectTCP( host, int(port), ProxyClientFactory( self ) )

        def clientConnectionMade( self, client ):
            serverCoroutine, clientCoroutine = self.factory.codec
            client.byteSink = clientCoroutine > callFromThreadWrapper( self.transport.write   )
            self.byteSink   = serverCoroutine > callFromThreadWrapper( client.transport.write )
            self.loseRemoteConnection = client.transport.loseConnection
            client.loseRemoteConnection = self.transport.loseConnection
            self.transport.resumeProducing()

        def dataReceived(self, data):
            for byte in data:
                self.byteSink.send( byte )


    class ProxyServerFactory ( protocol.Factory ):

        protocol = ProxyServer

        def __init__ ( self, destHostPort, codec ):
            self.destHostPort = destHostPort
            self.codec        = codec

    codec = GLOBALS.get( codecName )
    assert codec in CODECS, "codec must be one of %s, got %s" % ( formatGlobalNames( CODECS ), codecName )
    
    reactor.listenTCP( int(listenPort), ProxyServerFactory( destHostPort, codec(*args) ) )
    reactor.run()


@register( COMMANDS, 'test' )
def test( verbose=None ):
    import doctest
    doctest.testmod( verbose=verbose )

@usage
def main ( progname, command=None, *argv ):
    
    progname = os.path.basename( progname )

    argv = list( argv )

    if command == "-v":
        global verbose
        verbose = True
        command = argv.pop(0)

#    command = GLOBALS.get( command, None )

    if command in COMMANDS:

        try:
            result = COMMANDS[command]( *argv )

        except Exception, e:

            if verbose:
                raise

            result =  "%s: %s" % ( type(e).__name__, e )

    else:
        result = "usage: %s [-v] command tokenizationFunction,hashFunction,bitsPerWord [modelingFunction corpus [order [--abridged]]]\n" \
                 "usage: %s [-v] %s,%s,integer [%s filename [integer [--abridged]]]" % (
                     ( progname, progname ) + tuple( map( formatGlobalNames, ( TOKENIZERS, HASHES, MODELS ) ) ) )

    return result

if __name__ == "__main__":
    sys.exit( main( *sys.argv ) )
