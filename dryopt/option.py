class Option (object):
    __slots__ = ['default', 'parse', 'help']

    NoDefault = object() # immutable sentinel

    def __init__(self, default=NoDefault, parse=None, help=None):
        self.default = default
        if parse is None:
            assert default is not self.NoDefault, 'Either default or parse must be supplied.'
            parse = type(default)
        self.parse = parse
        self.help = help
        
