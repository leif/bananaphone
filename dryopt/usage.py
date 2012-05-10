class UsageError (Exception):
    def __init__(self):
        Exception.__init__(self)


class TooFewArgs (UsageError):
    def __init__(self, missing):
        UsageError.__init__(self)
        self.missing = missing

    def __str__(self):
        return 'Missing arguments: %s' % (', '.join(self.missing)) 

    
class DuplicateArg (UsageError):
    def __init__(self, name, old, new):
        UsageError.__init__(self)
        self.name = name
        self.old = old
        self.new = new
    
    def __str__(self):
        tmpl = 'Argument --%(name)s given multiple values: %(old)r and %(new)r'
        return tmpl % vars(self)


class InvalidValue (UsageError):
    def __init__(self, name, value, reason):
        UsageError.__init__(self)
        self.name = name
        self.value = value
        self.reason = reason
        
    def __str__(self):
        return 'Invalid value --%(name)s %(value)r: %(reason)s' % vars(self)
