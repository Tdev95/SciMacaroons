import unittest
from JWM import Macaroon
from SciMacaroons.enforcer import Enforcer
from SciMacaroons.scimacaroons import SciMacaroons


class TestEnforcer(unittest.TestCase):
    keys = {'key-for-test': 'random-test-key'}
    am = Macaroon('example.com', identifier='key-for-test', key=keys['key-for-test'])
    am.add_first_party_caveat('opt', 'optional claim')
    am.add_first_party_caveat('scope', 'write:/foo')
    scm = SciMacaroons(am)

    def test_enforcer(self):
        enforcer = Enforcer('example.com')
        enforcer.test(TestEnforcer.scm,
                      key=TestEnforcer.keys[TestEnforcer.scm.authorizing_macaroon.identifier],
                      authz='read',
                      path='/')

    def test_acls(self):
        enforcer = Enforcer('example.com')
        acls = enforcer.generate_acls(
            TestEnforcer.scm,
            TestEnforcer.keys[TestEnforcer.scm.authorizing_macaroon.identifier])
        self.assertEqual(acls, [('write', '/foo')])
