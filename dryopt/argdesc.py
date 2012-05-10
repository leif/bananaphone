import getopt
from dryopt.inspection import inspect_appfunc
from dryopt.option import Option
from dryopt.usage import InvalidValue


class ArgumentDescriptors (object):
    __slots__ = ['names', 'optmap', 'varg']

    def __init__(self, appfunc):
        opts, varg = inspect_appfunc(appfunc)
        self.names = [k for (k,_) in opts]
        self.optmap = dict(opts)
        self.varg = varg

    @property
    def defaults(self):
        d = {}
        for n, opt in self.optmap.items():
            if isinstance(opt, Option):
                default = opt.default
                if default is not opt.NoDefault:
                    d[n] = default
        return d

    def parse_commandline(self, args):
        chunks, args = self._getopt_chunk(args)
        kwargs = self._chunks_to_kwargs(chunks)
        for a in args:
            assert type(a) is str, `a`
        for (n, v) in kwargs.items():
            assert not isinstance(v, Option), `n, v`
        return (args, kwargs)
        
    def _getopt_chunk(self, args):
        return getopt.getopt(args, '', self._getopt_long_opts)

    def _chunks_to_kwargs(self, chunks):
        kwargs = self.defaults

        chunkDict = dict( chunks )

        for name, value in kwargs.items():
            if name not in chunkDict:
                kwargs[name] = self.optmap[name].parse(kwargs[name])

        for optname, vstr in chunks:
            # getopt postcondition:
            assert optname.startswith('--'), `optname, vstr`
            name = optname[2:]
            # getopt + self._getopt_spec postconditions ensures lookup success:
            opt = self.optmap[name]
            if opt.parse is bool:
                assert vstr == '', `vstr` # getopt + self._getopt_spec postcondition.
                v = True
            else:
                try:
                    v = opt.parse(vstr)
                except Exception, e:
                    raise InvalidValue(name, vstr, str(e))
            assert not isinstance(v, Option), `optname, name, vstr, v`
            kwargs[name] = v

        return kwargs
                
    @property
    def _getopt_long_opts(self):
        longopts = ['help']
        for name, opt in self.optmap.items():
            if not opt is None:
                if opt.parse is not bool:
                    name += '='
                longopts.append(name)
        return longopts

