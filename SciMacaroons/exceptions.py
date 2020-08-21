class EnforcementError(Exception):
    """
    A generic error during the enforcement of a SciToken.
    """


class InvalidPathError(EnforcementError):
    """
    An invalid test path was provided to the Enforcer object.

    Test paths must be absolute paths (start with '/')
    """


class InvalidAuthorizationResource(EnforcementError):
    """
    A scope was encountered with an invalid authorization.

    Examples include:
       - Authorizations that require paths (read, write) but none
         were included.
       - Scopes that include relative paths (read:~/foo)
    """
