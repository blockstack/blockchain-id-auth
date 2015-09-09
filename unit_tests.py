#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    ~~~~~
    :copyright: (c) 2015 by Halfmoon Labs, Inc.
    :license: MIT, see LICENSE for more details.
"""

import ast
import json
import uuid
import traceback
import unittest
from test import test_support
from pybitcoin import BitcoinPrivateKey
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey
)

from blockchainauth import Tokenizer, AuthRequest, AuthResponse, OnenameAPIResolver
from settings import ONENAME_APP_ID, ONENAME_APP_SECRET


class AuthRequestTest(unittest.TestCase):
    def setUp(self):
        self.private_key_hex = 'a5c61c6ca7b3e7e55edee68566aeab22e4da26baa285c7bd10e8d2218aa3b22901'
        self.public_key_hex = '027d28f9951ce46538951e3697c62588a87f1f1f295de4a14fdd4c780fc52cfe69'
        self.domain = 'onename.com'
        self.permissions = ['blockchainid']
        self.private_key = BitcoinPrivateKey(self.private_key_hex, compressed=True)
        self.sample_encoded_token = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3N1ZWRBdCI6IjE0NDA3MTM0MTQuMTkiLCJjaGFsbGVuZ2UiOiIxZDc4NTBkNy01YmNmLTQ3ZDAtYTgxYy1jMDA4NTc5NzY1NDQiLCJwZXJtaXNzaW9ucyI6WyJibG9ja2NoYWluaWQiXSwiaXNzdWVyIjp7InB1YmxpY0tleSI6IjAzODI3YjZhMzRjZWJlZTZkYjEwZDEzNzg3ODQ2ZGVlYWMxMDIzYWNiODNhN2I4NjZlMTkyZmEzNmI5MTkwNjNlNCIsImRvbWFpbiI6Im9uZW5hbWUuY29tIn19.96Q_O_4DX8uPy1enosEwS2sIcyVelWhxvfj2F8rOvHldhqt9YRYilauepb95DVnmpqpCXxJb7jurT8auNCbptw'
        self.sample_decoded_token_payload = {"issuedAt": "1440713414.19", "challenge": "1d7850d7-5bcf-47d0-a81c-c00857976544", "issuer": {"publicKey": "03827b6a34cebee6db10d13787846deeac1023acb83a7b866e192fa36b919063e4", "domain": "onename.com"}, "permissions": ["blockchainid"]}
        self.resolver = OnenameAPIResolver(ONENAME_APP_ID, ONENAME_APP_SECRET)

    def tearDown(self):
        pass

    def test_auth_request_token_encoding(self):
        auth_request = AuthRequest(
            self.private_key.to_pem(), self.private_key.public_key().to_hex(),
            self.domain, self.permissions)
        auth_request_token = auth_request.token()

        is_valid_token = AuthRequest.verify(auth_request_token, self.resolver)
        self.assertTrue(is_valid_token)

    def test_auth_request_token_decoding(self):
        decoded_token = AuthRequest.decode(self.sample_encoded_token)
        decoded_token_payload = decoded_token['payload']
        self.assertEqual(decoded_token_payload, self.sample_decoded_token_payload)


class AuthResponseTest(unittest.TestCase):
    def setUp(self):
        self.private_key_hex = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
        self.public_key_hex = '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479'
        self.master_public_key = 'xpub661MyMwAqRbcFQVrQr4Q4kPjaP4JjWaf39fBVKjPdK6oGBayE46GAmKzo5UDPQdLSM9DufZiP8eauy56XNuHicBySvZp7J5wsyQVpi2axzZ'
        self.master_private_key = 'xprv9s21ZrQH143K2vRPJpXPhcT12MDpL3rofvjagwKn4yZpPPFpgWn1cy1Wwp3pk78wfHSLcdyZhmEBQsZ29ZwFyTQhhkVVa9QgdTC7hGMB1br'
        self.chain_path = 'bd62885ec3f0e3838043115f4ce25eedd22cc86711803fb0c19601eeef185e39'
        self.private_key = BitcoinPrivateKey(self.private_key_hex, compressed=True)
        self.blockchainid = 'ryan'
        self.challenge = '7cd9ed5e-bb0e-49ea-a323-f28bde3a0549'
        self.sample_encoded_token = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3N1ZWRBdCI6IjE0NDA3MTM0MTQuODUiLCJjaGFsbGVuZ2UiOiI3Y2Q5ZWQ1ZS1iYjBlLTQ5ZWEtYTMyMy1mMjhiZGUzYTA1NDkiLCJpc3N1ZXIiOnsicHVibGljS2V5IjoiMDNmZGQ1N2FkZWMzZDQzOGVhMjM3ZmU0NmIzM2VlMWUwMTZlZGE2YjU4NWMzZTI3ZWE2NjY4NmMyZWE1MzU4NDc5IiwiY2hhaW5QYXRoIjoiYmQ2Mjg4NWVjM2YwZTM4MzgwNDMxMTVmNGNlMjVlZWRkMjJjYzg2NzExODAzZmIwYzE5NjAxZWVlZjE4NWUzOSIsInB1YmxpY0tleWNoYWluIjoieHB1YjY2MU15TXdBcVJiY0ZRVnJRcjRRNGtQamFQNEpqV2FmMzlmQlZLalBkSzZvR0JheUU0NkdBbUt6bzVVRFBRZExTTTlEdWZaaVA4ZWF1eTU2WE51SGljQnlTdlpwN0o1d3N5UVZwaTJheHpaIiwiYmxvY2tjaGFpbmlkIjoicnlhbiJ9fQ.oO7ROPKq3T3X0azAXzHsf6ub6CYy5nUUFDoy8MS22B3TlYisqsBrRtzWIQcSYiFXLytrXwAdt6vjehj3OFioDQ'
        self.sample_decoded_token_payload = {"issuedAt": "1440713414.85", "challenge": "7cd9ed5e-bb0e-49ea-a323-f28bde3a0549", "issuer": {"publicKey": "03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479", "blockchainid": "ryan", "publicKeychain": "xpub661MyMwAqRbcFQVrQr4Q4kPjaP4JjWaf39fBVKjPdK6oGBayE46GAmKzo5UDPQdLSM9DufZiP8eauy56XNuHicBySvZp7J5wsyQVpi2axzZ", "chainPath": "bd62885ec3f0e3838043115f4ce25eedd22cc86711803fb0c19601eeef185e39"}}
        self.resolver = OnenameAPIResolver(ONENAME_APP_ID, ONENAME_APP_SECRET)

    def tearDown(self):
        pass

    def test_auth_response_token_encoding(self):
        challenge = str(uuid.uuid4())
        auth_response = AuthResponse(
            self.private_key.to_pem(), self.private_key.public_key().to_hex(),
            self.challenge, self.blockchainid, self.master_public_key,
            self.chain_path)
        auth_response_token = auth_response.token()

        is_valid_token = AuthResponse.verify(auth_response_token, self.resolver)
        self.assertTrue(is_valid_token)

    def test_anon_auth_response_encoding(self):
        challenge = str(uuid.uuid4())
        auth_response = AuthResponse(
            self.private_key.to_pem(), self.private_key.public_key().to_hex(),
            self.challenge)
        auth_response_token = auth_response.token()

        is_valid_token = AuthResponse.verify(auth_response_token, self.resolver)
        self.assertTrue(is_valid_token)

    def test_auth_response_token_decoding(self):
        decoded_token = AuthResponse.decode(self.sample_encoded_token)
        decoded_token_payload = decoded_token['payload']
        self.assertEqual(decoded_token_payload, self.sample_decoded_token_payload)


def test_main():
    test_support.run_unittest(
        AuthRequestTest,
        AuthResponseTest
    )

if __name__ == '__main__':
    test_main()
