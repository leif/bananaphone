import inspect
from dryopt.option import Option


def inspect_appfunc(f):
    args, vargs, varkw, defaults = inspect.getargspec(f)
    assert varkw is None, '**args are disallowed in application functions.'
    if defaults is None:
        defaults = ()
    assert type(defaults) is tuple, `defaults`

    for d in defaults:
        assert isinstance(d, Option), \
            'Application defaults must be Option instances.'

    defaults = tuple([None] * (len(args) - len(defaults))) + defaults
    assert len(defaults) == len(args), `defaults, args`

    return (zip(args, defaults), vargs)

    
