#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    ~~~~~
    :copyright: (c) 2015 by Halfmoon Labs, Inc.
    :copyright: (c) 2017 by Stanislav Pankratov
    :license: MIT, see LICENSE for more details.
"""

import json
import requests_mock
import unittest
from test import test_support
from pybitcoin import BitcoinPrivateKey, BitcoinPublicKey
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from blockchainauth import AuthRequest, AuthResponse
from blockchainauth.dids import get_address_from_did
from tests.test_data import PRIVATE_KEY, PUBLIC_KEY, \
    REQUEST_SAMPLE_ENCODED_TOKEN, REQUEST_SAMPLE_DECODED_TOKEN,\
    RESPONSE_SAMPLE_ENCODED_TOKEN, RESPONSE_SAMPLE_DECODED_TOKEN, RYAN_PROFILE
from blockchainauth.tokenizer import Tokenizer
from blockchainauth.verification import do_public_keys_match_username, LOCALHOST_CORE_API, NAME_LOOKUP_URL


class AuthRequestTest(unittest.TestCase):
    def setUp(self):
        self.private_key_hex = str(PRIVATE_KEY)
        self.public_key_hex = str(PUBLIC_KEY)
        self.domain_name = 'localhost:3000'
        self.private_key = BitcoinPrivateKey(self.private_key_hex)
        self.public_key = BitcoinPublicKey(self.public_key_hex)
        self.sample_encoded_token = REQUEST_SAMPLE_ENCODED_TOKEN
        self.sample_decoded_token = REQUEST_SAMPLE_DECODED_TOKEN
        self.maxDiff = None

    def tearDown(self):
        pass

    def test_auth_request_token_encoding(self):
        # valid AuthRequest
        auth_request = AuthRequest(self.private_key_hex, self.domain_name)
        auth_request_token = auth_request.token()

        decoded_token = AuthRequest.decode(auth_request_token)
        payload = decoded_token['payload']
        self.assertEqual(payload['public_keys'][0], self.public_key_hex)
        self.assertEqual(get_address_from_did(payload['iss']), self.public_key.address())
        self.assertEqual(payload['scopes'], [])
        self.assertEqual(payload['manifest_uri'], self.domain_name + '/manifest.json')

        self.assertTrue(AuthRequest.verify(auth_request_token))

        # invalid AuthRequest
        auth_request = AuthRequest(self.private_key_hex, self.domain_name)
        auth_request_token = auth_request.token()[:-1]

        self.assertFalse(AuthRequest.verify(auth_request_token))

    def test_auth_request_token_decoding(self):
        decoded_token = AuthRequest.decode(self.sample_encoded_token)
        self.assertEqual(decoded_token, self.sample_decoded_token)

    def test_custom_openssl_backend(self):
        auth_request = AuthRequest(self.private_key_hex, self.domain_name, crypto_backend=openssl_backend)
        auth_request_token = auth_request.token()
        self.assertTrue(AuthRequest.verify(auth_request_token))


class AuthResponseTest(unittest.TestCase):
    def setUp(self):
        self.private_key_hex = str(PRIVATE_KEY)
        self.public_key_hex = str(PUBLIC_KEY)
        self.private_key = BitcoinPrivateKey(self.private_key_hex)
        self.public_key = BitcoinPublicKey(self.public_key_hex)
        self.profile = RYAN_PROFILE
        self.username = 'ryan.id'
        self.sample_encoded_token = RESPONSE_SAMPLE_ENCODED_TOKEN
        self.sample_decoded_token = RESPONSE_SAMPLE_DECODED_TOKEN

    def tearDown(self):
        pass

    def test_auth_response_token_encoding(self):
        # without username, testing basics
        auth_response = AuthResponse(self.private_key_hex, RYAN_PROFILE)
        auth_response_token = auth_response.token()

        decoded_token = AuthResponse.decode(auth_response_token)
        payload = decoded_token['payload']
        self.assertEqual(payload['public_keys'][0], self.public_key_hex)
        self.assertEqual(get_address_from_did(payload['iss']), self.public_key.address())
        self.assertEqual(payload['profile'], self.profile)
        self.assertEqual(payload['username'], None)

        self.assertTrue(AuthResponse.verify(auth_response_token))

        # with username
        with requests_mock.mock() as m:
            m.get(LOCALHOST_CORE_API + NAME_LOOKUP_URL + self.username,
                  text=json.dumps({'address': self.public_key.address()}))
            auth_response = AuthResponse(self.private_key_hex, RYAN_PROFILE, self.username)
            auth_response_token = auth_response.token()

            self.assertTrue(do_public_keys_match_username(auth_response_token, Tokenizer(),
                                                          AuthResponse.decode(auth_response_token)))
            self.assertTrue(AuthResponse.verify(auth_response_token))

    def test_auth_response_token_decoding(self):
        decoded_token = AuthResponse.decode(self.sample_encoded_token)
        self.assertEqual(decoded_token, self.sample_decoded_token)


def test_main():
    test_support.run_unittest(
        AuthRequestTest,
        AuthResponseTest
    )

if __name__ == '__main__':
    test_main()
