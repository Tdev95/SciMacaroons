"""
SciMacaroons reference library.

This library provides the primitives necessary for working with SciMacaroons
authorization tokens. SciMacaroons tries to bring SciTokens functionality over
to a Macaroon-based bearer token.
"""

import JWM


class SciMacaroons(JWM.JWM):

    def __init__(self, authorizing_macaroon, discharge_macaroons=None):
        """
        Construct a SciMacaroons object.

        :param authorizing_macaroon: An authorizing Macaroon
        :type authorizing_macaroon: Macaroon
        :param discharge_macaroons: A list of discharge Macaroons
        :type discharge_macaroons: List of Macaroons
        """
        return super().__init__(authorizing_macaroon, discharge_macaroons=discharge_macaroons)

    def serialize(self):
        """
        Serialize the existing SciMacaroons object.
        :return str: base64 encoded token
        """
        return super().serialize()

    @classmethod
    def deserialize(cls, serialized_token):
        """
        Builds (Deserializes) a SciMacaroons object from a string

        :param string: string to be deserialized
        :type string: string
        :returns: new SciMacaroons object representing the deserialized string
        :rtype: SciMacaroons

        :raises: DeserializationException
        """
        return super().deserialize(serialized_token)
