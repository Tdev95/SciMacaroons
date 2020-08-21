import unittest
from JWM import Macaroon
from SciMacaroons.scimacaroons import SciMacaroons


class TestSciMacaroons(unittest.TestCase):
    keys = {'secret key': 'a secret key'}
    am = Macaroon(location='test.com', identifier='secret key', key=keys['secret key'])
    am.add_first_party_caveat('key', 'value')

    def test_scm(self):
        """
        basic test to see whether initalization, serialization and deserialization
        can be completed without errors
        """
        scm = SciMacaroons(TestSciMacaroons.am)
        self.assertEqual(scm.authorizing_macaroon.identifier,
                         SciMacaroons.deserialize(scm.serialize()).authorizing_macaroon.identifier)
