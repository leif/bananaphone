#!/usr/bin/env python
# -*- coding: utf-8 -*-
r""" Reverse Hash Encoding

This is an implementation of a steganographic encoding scheme which transforms
a stream of binary data into a stream of tokens (eg, something resembling
natural language text) such that the stream can be decoded by concatenating the
hashes of the tokens.

TLDR: SSH over Markov chains

The encoder is given a word size (number of bits), a tokenization function (eg,
split text on whitespace), a hash function (eg, sha1), a corpus, and a modeling
function (eg, a markov model, or a weighted random model). The range of the
hash function is truncated to the word size. The model is built by tokenizing
the corpus and hashing each token with the truncated hash function. For the
model to be usable, there must be enough tokens to cover the entire hash space
(2^(word size) hashes). After the model is built, the input data bytes are
scaled up or down to the word size (eg, scaling [255, 18] from 8-bit bytes to
4-bit words produces [15, 15, 1, 2]) and finally each scaled input word is
encoded by asking the model for a token which hashes to that word. (The
encoder's model can be thought of as a probabilistic reverse hash function.)


FUTURE IDEAS
This was written as a fun experimental proof-of-concept hack, and in its
present form it is TRIVIALLY DETECTABLE since there is no encryption used.
(When you ssh over it, an observer only needs to guess your tokenization
function, hash function and word size to see that you are using ssh.) It would
be easy enough to add some shared-secret crypto, but the beginning of an SSH or
SSL session (and certain activities within them) would still be detectable
using timing analysis.

I have a vague idea for another layer providing timing cover for binary streams
(adding traffic to make the apparent throughput constant or randomly varied);
To make a steganographic stream encoder which is actually resistant to
steganalysis, perhaps encryption should be applied on top of that layer (under
this one? Note: these are tricky problems and I don't really know what I'm
doing :)

Or instead, maybe this could be layered under the Tor Project's obfsproxy?

Another idea: For encoding short messages, one could use the markov model and
the weighted random model to provide an auto-completing text-entry user
interface where entirely innocuous (human-meaningful) cover messages could be
composed.


USAGE NOTES
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
adherence is written to stderr periodically.


EXAMPLE USAGE:

encode "Hello\n" at 13 bits per word, using a dictionary and random picker:
    echo Hello | ./bananaphone.py rh_encoder words,sha1,13 random /usr/share/dict/words

decode "Hello\n" from 13-bit words:
    echo "discombobulate aspens brawler Gödel's" | ./bananaphone.py rh_decoder words,sha1,13

start a proxy listener for $sshhost, using an abridged first-order markov encoder with 1 bit per word:
    socat TCP4-LISTEN:1234,fork EXEC:'bash -c "./bananaphone.py\\ rh_decoder\\ words,sha1,1|socat\\ TCP4\:$sshhost\:22\\ -|./bananaphone.py\\ rh_encoder\\ words,sha1,1\\ markov\\ corpus.txt\\ 1\\ --abridged"'

connect to the ssh host through the $proxyhost:
    ssh user@host -oProxyCommand="./bananaphone.py rh_encoder words,sha1,1 markov corpus.txt|socat TCP4:$proxyhost:1234 -|./bananaphone.py rh_decoder words,sha1,1"
"""

__author__    = "Leif Ryge <leif@synthesize.us>"
__copyright__ = "No Rights Reserved, Uncopyright 2011"

import os, sys
from random    import choice
from hashlib   import md5, sha1, sha224, sha256, sha384, sha512
from itertools import islice, imap

HASHES  = [ md5, sha1, sha224, sha256, sha384, sha512 ]
GLOBALS = globals()

global verbose
verbose = False

def debug ( message ):
    if verbose:
        sys.stderr.write( "%s\n" % (message,) )

def debugStream ( stream ):
    for item in stream:
        debug( "debugStream: %s" % (item,) )
        yield item

def formatGlobalNames ( objectList ):
    return "<%s>" % "|".join( k for k,v in GLOBALS.items() if v in objectList )

def appendTo ( objectList ):
    def decorator( function ):
        objectList.append( function )
        return function
    return decorator


def changeWordSize ( words, inSize, outSize ):
    """
    >>> list( changeWordSize( [255, 18], 8, 1 ) )
    [1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0]
    >>> list( changeWordSize( [255, 18], 8, 4 ) )
    [15, 15, 1, 2]
    >>> list( changeWordSize( [15, 15, 1, 2], 4, 8 ) )
    [255, 18]

    NOTE: this will sometimes add trailing null words when inSize is not a
    factor or multiple of outSize:
    >>> list( changeWordSize( [255, 18], 8, 5 ) )
    [31, 28, 9, 0]
    """
    assert inSize  > 0
    assert outSize > 0
    bits  = 0
    value = 0
    for word in words:
        assert type(word) in (int, long), "words must be int or long, got %s" % ( type( word ), )
        assert 0 <= word < 2 ** inSize  , "words must be in range 0 to 2**%s-1, got %s" % ( inSize, word )
        value  = value << inSize
        value += word
        bits  += inSize
        while outSize <= bits:
            bits    -= outSize
            newWord  = value >> bits
            value   -= newWord << bits
            yield newWord
    if bits:
        yield value << (outSize - bits)


def buildWeightedRandomModel ( corpusTokens, hash ):
    model = {}
    for token in corpusTokens:
        model.setdefault( hash( token ), [] ).append( token )
    return model


def ngram ( sequence, n ):
    """
    >>> list( ngram( range(5), 2 ) )
    [(0, 1), (1, 2), (2, 3), (3, 4)]
    """
    sequence = iter( sequence )
    prev = tuple( islice( sequence, n ) )
    for next in sequence:
        yield prev
        prev = prev[ 1: ] + ( next, )
    yield prev


def ngramPlusOne ( sequence, n ):
    """
    >>> list( ngramPlusOne( range(5), 1 ) )
    [((0,), 1), ((1,), 2), ((2,), 3), ((3,), 4)]
    >>> list( ngramPlusOne( range(5), 2 ) )
    [((0, 1), 2), ((1, 2), 3), ((2, 3), 4)]
    """
    for gram in ngram( sequence, n + 1 ):
        yield ( gram[ :-1 ], gram[ -1 ] )


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
    markovModel = buildMarkovModel( ngramPlusOne( tokens, order ) )
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
    assert 0 <= percentFull <= 100
    return percentFull


def removeIncompleteSpaces ( model, bits ):

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


def truncateHash ( hash, bits ):

    def truncatedHash ( input ):
        return int( hash( input ).hexdigest(), 16 ) % ( 2 ** bits )
    
    return truncatedHash


def parseEncodingSpec ( encodingSpec ):
    
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
def bytes ( byteStream ):
    for byte in byteStream:
        yield byte


@appendTo(TOKENIZERS)
def asciiPrintableBytes ( byteStream ):
    for byte in byteStream:
        if 0x20 <= ord( byte ) <= 0x7e:
            yield byte


def streamTokenizer ( stopBytes ):
    "Return a tokenizer which yields a token whenever it sees a byte in stopBytes"
    def tokenizer ( byteStream ):
        value = []
        for byte in byteStream:
            value.append( byte )
            if byte in stopBytes:
                yield "".join( value )
                value = []
    return tokenizer


@appendTo(TOKENIZERS)
def words ( stream ):
    "generator equiv of [ s+' ' for s in str(byteStream).strip().split() ]"
    for token in streamTokenizer( " \n" )( stream ):
        if token not in ( " ", "\n" ):
            yield token.strip() + ' '


lines  = appendTo(TOKENIZERS)( streamTokenizer( "\n" ) )
words2 = appendTo(TOKENIZERS)( streamTokenizer( " \n.,;?!" ) )
words3 = appendTo(TOKENIZERS)( lambda stream: ( word[:-1]+' ' if word.endswith("\n") and not word == "\n"
                                                            else word
                                                             for word in streamTokenizer( tuple( " \n.,;?!" ) )( stream ) ) )


MODELS = []

@appendTo(MODELS)
def markov ( corpusTokens, truncatedHash, bits, order=1, abridged=None ):

    order       = int( order )
    randomModel = buildWeightedRandomModel( corpusTokens, truncatedHash )
    percentFull = getPercentFull( randomModel, bits )
    assert percentFull == 100, "not enough tokens for %s-bit hashing (%s%% there)" % (bits, percentFull)
    model = buildHashPartitionedMarkovModel( corpusTokens, truncatedHash, order )
    debug( "%s states (%s tokens, %s unique, order=%s)" % ( len(model), len(corpusTokens), len( set(corpusTokens) ), order ) )

    if abridged == "--abridged":
        abridgedMarkovModel = removeIncompleteSpaces( model, bits )
        incompleteStates  = len(model) - len(abridgedMarkovModel)
        debug( "%s states which lead to incomplete hash spaces will not be used." % ( incompleteStates, ) )
        model = abridgedMarkovModel

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
def random ( corpusTokens, truncatedHash, bits ):

    corpusTokens = list( corpusTokens )

    model = buildWeightedRandomModel( corpusTokens, truncatedHash )
    
    percentFull = getPercentFull( model, bits )
    assert percentFull == 100, "not enough tokens for %s-bit hashing (%s%% there)" % (bits, percentFull)
    
    debug( "built weighted random model from %s tokens (%s unique)" % ( len(corpusTokens), len(set(corpusTokens)) ) )

    def encode( value ):
        return choice( model[ value ] )
    
    return encode



COMMANDS = []

@appendTo(COMMANDS)
def rh_decoder ( encodingSpec ):

    tokenize, hash, bits = parseEncodingSpec( encodingSpec )
    truncatedHash = truncateHash( hash, bits )

    def process ( byteStream ):
        hashStream = imap( truncatedHash, tokenize( byteStream ) )
        return imap( chr, changeWordSize( hashStream, bits, 8 ) )

    return process


@appendTo(COMMANDS)
def rh_encoder ( encodingSpec, modelName, corpusFilename, *args ):

    tokenize, hash, bits = parseEncodingSpec( encodingSpec )
    truncatedHash = truncateHash( hash, bits )

    model = GLOBALS.get( modelName )
    assert model in MODELS, "model must be one of %s, got %s" % ( formatGlobalNames( MODELS ), modelName )
    
    corpusTokens = list( tokenize( readTextFile( corpusFilename ) ) )

    encode = model( corpusTokens, truncatedHash, bits, *args )

    def process ( byteStream ):
        ordinalStream = imap( ord, byteStream )
        return imap( encode, changeWordSize( ordinalStream, 8, bits ) )
    
    return process


@appendTo(COMMANDS)
def rh_print_corpus_stats ( encodingSpec, corpusFilename, order=1 ):

    tokenize, hash, bits = parseEncodingSpec( encodingSpec )
    corpusTokens = list( tokenize( readTextFile( corpusFilename ) ) )

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


def runPipeline ( process ):
    "run a byte-consuming generator function on stdin/stdout"
    stdout = os.fdopen(sys.stdout.fileno(), 'w', 0) # do not want buffering
    stdin  = os.fdopen(sys.stdin .fileno(), 'r', 0) # do not want buffering
    stdinBytestream = iter( lambda: stdin.read(1), '' ) # do want byte iterator
    map( stdout.write, process( stdinBytestream ) ) # run process


def main ( progname, command=None, *argv ):

    progname = os.path.basename( progname )

    argv = list( argv )

    if command == "-v":
        global verbose
        verbose = True
        command = argv.pop(0)

    command = GLOBALS.get( command, None )

    if command in COMMANDS:
    
        try:
            result = command( *argv )

            if callable( result ):
                result = runPipeline( result )

        except Exception, e:

            if verbose:
                raise
            
            result =  "%s: %s" % ( type(e).__name__, e )

    else:
        result = "usage: %s [-v] command tokenizationFunction,hashFunction,bitsPerWord [modelingFunction corpus [order [--abridged]]]\n" \
                 "usage: %s [-v] %s %s,%s,integer [%s filename [integer [--abridged]]]" % (
                     ( progname, progname ) + tuple( map( formatGlobalNames, ( COMMANDS, TOKENIZERS, HASHES, MODELS ) ) ) )

    return result

if __name__ == "__main__":
    sys.exit( main( *sys.argv ) )
