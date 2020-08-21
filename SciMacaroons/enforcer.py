from JWM import Verifier
from SciMacaroons.exceptions import EnforcementError, InvalidPathError, InvalidAuthorizationResource
import SciMacaroons.urltools as urltools
import time
import logging

LOGGER = logging.getLogger('scimacaroons')


class Enforcer():
    """
    Enforce SciMacaroons-specfic validation logic

    Allows one to test if a given SciMacaroon has a particular authorization

    This class is NOT thread safe; a separate object is needed for every thread.
    """

    _authz_requiring_path = set(["read", "write"])

    # An array of versions of scitokens that we understand and can enforce
    _versions_understood = [1]

    def __init__(self, issuer, site=None, audience=None):
        self._issuer = issuer
        self.last_failure = None
        if not self._issuer:
            raise EnforcementError("Issuer must be specified.")
        self._audience = audience
        self._site = site
        self._test_access = False
        self._test_authz = None
        self._test_path = None
        self._token_scopes = set()
        self._now = 0
        # set up Verifier
        self._verifier = Verifier()
        self._validate_scope = Enforcer._ScopeValidator(self)
        self.add_validator("exp", self._validate_exp)
        self.add_validator("nbf", self._validate_nbf)
        self.add_validator("iss", self._validate_iss)
        self.add_validator("iat", self._validate_iat)
        self.add_validator("site", self._validate_site)
        self.add_validator("aud", self._validate_aud)
        self.add_validator("scope", self._validate_scope)
        self.add_validator("jti", self._validate_jti)
        self.add_validator("sub", self._validate_sub)
        self.add_validator("ver", self._validate_ver)
        self.add_validator("opt", self._validate_opt)

    def test(self, scimacaroon, key, authz, path=None):
        """
        Test whether a given SciMacaroon can be verified and validated within the
        current enforcer context.
        """
        self._reset_state()
        self._test_access = True

        critical_claims = set(["scope"])

        if not path and (authz in self._authz_requiring_path):
            raise InvalidPathError("Enforcer provided with an empty path.")
        if path and not path.startswith("/"):
            raise InvalidPathError(
                "Enforcer was given an invalid relative path to test; absolute path required.")

        self._test_path = path
        self._test_authz = authz
        self.last_failure = None

        for claim in critical_claims:
            self._verifier.add_critical_claim(claim)
        try:
            self._verifier.verify(scimacaroon, key)
        # except ValidationFailure as validation_failure:
        except Exception as validation_failure:
            self.last_failure = str(validation_failure)
            return False
        return True

    def add_validator(self, claim, callback):
        """
        Add a user-defined validator in addition to the default enforcer logic
        """
        self._verifier.add_validator(claim, callback)

    def _reset_state(self):
        """
        Reset the internal state variables of the Enforcer object. Automatically
        invoked each time the Enforcer is used to test or generate_acls
        """
        self._test_authz = None
        self._test_path = None
        self._test_access = False
        self._token_scopes = set()
        self._now = time.time()
        self.last_failure = None

    # callback functions

    def _validate_exp(self, value):
        exp = float(value)
        return exp >= self._now

    def _validate_nbf(self, value):
        nbf = float(value)
        return nbf < self._now

    def _validate_iss(self, value):
        return self._issuer == value

    def _validate_iat(self, value):
        return float(value) < self._now

    def _validate_site(self, value):
        if not self._site:
            return False
        return value == self._site

    def _validate_aud(self, value):
        if not self._audience:
            return False
        if isinstance(self._audience, list):
            return value in self._audience
        return value == self._audience

    def _validate_ver(self, value):
        if value in self._versions_understood:
            return True
        else:
            return False

    @classmethod
    def _validate_opt(self, value):
        """
        Opt is optional information.  We don't know what's in there, so just
        return true.
        """
        del value
        return True

    @classmethod
    def _validate_sub(self, value):
        """
        SUB, or subject, should always pass.  It's mostly used for identifying
        a tokens origin.
        """
        # Fix for unused argument
        del value
        return True

    @classmethod
    def _validate_jti(self, value):
        """
        JTI, or json token id, should always pass.  It's mostly used for logging
        and auditing.
        """
        global LOGGER
        LOGGER.info("Validating SciToken with jti: {0}".format(value))
        return True

    # scope
    class _ScopeValidator:
        def __init__(self, enforcer):
            self.enforcer = enforcer

        def __call__(self, value):
            self.token_scopes = value
            if not isinstance(value, str):
                raise InvalidAuthorizationResource(
                    "Scope is invalid.  Must be a space separated string")
            if self.enforcer._test_access:
                if not self.enforcer._test_path:
                    norm_requested_path = '/'
                else:
                    norm_requested_path = urltools.normalize_path(self.enforcer._test_path)
                # Split on spaces
                for scope in value.split(" "):
                    authz, norm_path = self._check_scope(scope)
                    if (self.enforcer._test_authz == authz) and norm_requested_path.startswith(norm_path):
                        return True
                return False
            else:
                # Split on spaces
                for scope in value.split(" "):
                    authz, norm_path = self._check_scope(scope)
                    self.enforcer._token_scopes.add((authz, norm_path))
                return True

        def _check_scope(self, scope):
            """
            Given a scope, make sure it contains a resource
            for scope types that require resources.

            Returns a tuple of the (authz, path).  If path is
            not in the scope (and is not required to be explicitly inside
            the scope), it will default to '/'.
            """
            info = scope.split(":", 1)
            authz = info[0]
            if authz in self.enforcer._authz_requiring_path and (len(info) == 1):
                raise InvalidAuthorizationResource(
                    "Token contains an authorization requiring a resource"
                    "(path), but no path is present")
            if len(info) == 2:
                path = info[1]
                if not path.startswith("/"):
                    raise InvalidAuthorizationResource("Token contains a relative path in scope")
                norm_path = urltools.normalize_path(path)
            else:
                norm_path = '/'
            return (authz, norm_path)

    def generate_acls(self, token, key):
        """
        Given a SciMacaroons object and the expected issuer, return the valid ACLs.
        """
        self._reset_state()

        critical_claims = set(["scope"])
        for claim in critical_claims:
            self._verifier.add_critical_claim(claim)
        try:
            self._verifier.verify(token, key)
        # except ValidationFailure as verify_fail:
        except Exception as verify_fail:
            self.last_failure = str(verify_fail)
            raise
        return list(self._token_scopes)
