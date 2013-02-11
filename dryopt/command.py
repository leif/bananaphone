import sys
from dryopt.argdesc import ArgumentDescriptors
from dryopt.option import Option
from dryopt.usage import UsageError, DuplicateArg, TooFewArgs


class Command (object):
    """
    This decorates a commandline-oriented application function.
    """
    __slots__ = ['target', 'descriptors', 'desc']

    def __init__(self, appfunc, desc=None):
        self.target = appfunc
        self.descriptors = ArgumentDescriptors(appfunc)
        self.desc = desc

    @property
    def name(self):
        return self.target.__name__

    @property
    def usage(self):
        width = max(map(len,self.descriptors.names)) + 3
        return "\n".join(
            ("--%-"+str(width)+"s=%s") % (name, name)
            if self.descriptors.optmap[ name ].default == Option.NoDefault else ""
            for name in self.descriptors.names )

    def __call__(self, *a, **kw):
        '''
        Emulate python call.
        '''
        kwargs = {}

        # Positional non-vargs:
        for (name, value) in zip(self.descriptors.names, a):
            kwargs[name] = self.descriptors.optmap[name].parse( value )

        # Key word vargs:
        for (name, value) in kw.items():
            if kwargs.has_key(name):
                raise DuplicateArg(name, kwargs[name], value)
            try:
                kwargs[name] = self.descriptors.optmap[name].parse( value )
            except KeyError:
                raise TypeError( "%s() got got an unexpected keyword argument %r" % ( self.name , name ) )


        # Defaults:
        for (name, opt) in self.descriptors.optmap.items():
            if (opt is not None) and not kwargs.has_key(name):
                d = opt.default
                if d is not Option.NoDefault:
                    kwargs[name] = opt.parse( d )

        vargs = a[len(self.descriptors.names):]

        argsgiven = len(kwargs)
        argsneeded = len(self.descriptors.names)
        if argsgiven < argsneeded:
            raise TooFewArgs(self.descriptors.names[:argsneeded - argsgiven])

        return self.target(*vargs, **kwargs)

    def commandline_call(self, args = sys.argv[1:]):
        try:
            args, kwargs = self.descriptors.parse_commandline(args)
            return self(*args, **kwargs)
        except UsageError, e:
            raise SystemExit('%s\n\n%s' % (e, self.usage))

