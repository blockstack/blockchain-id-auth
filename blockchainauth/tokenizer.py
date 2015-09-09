#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    An interface for encoding and decoding JSON Web Tokens (JWTs)
    ~~~~~
    :copyright: (c) 2015 by Halfmoon Labs, Inc.
    :license: MIT, see LICENSE for more details.
"""

import json
import binascii
import traceback
from collections import Mapping

from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key, load_pem_private_key, load_der_public_key,
    load_pem_public_key
)
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey
)

from jwt.utils import (
    base64url_encode, base64url_decode, der_to_raw_signature,
    raw_to_der_signature
)
from jwt import DecodeError
from .utils import json_encode
from .keys import load_signing_key


class Tokenizer():
    def __init__(self):
        self.token_type = 'JWT'
        self.signing_algorithm = 'ES256'

    def _get_signer(self, signing_key):
        return signing_key.signer(ec.ECDSA(hashes.SHA256()))

    def encode(self, payload, signing_key):
        if not isinstance(payload, Mapping):
            raise TypeError('Expecting a mapping object, as only '
                            'JSON objects can be used as payloads.')

        token_segments = []

        signing_key = load_signing_key(signing_key)

        # prepare header
        header = {'typ': self.token_type, 'alg': self.signing_algorithm}
        token_segments.append(base64url_encode(json_encode(header)))

        # prepare payload
        token_segments.append(base64url_encode(json_encode(payload)))

        # prepare signature
        signing_input = b'.'.join(token_segments)
        signer = self._get_signer(signing_key)
        signer.update(signing_input)
        signature = signer.finalize()
        raw_signature = der_to_raw_signature(signature, signing_key.curve)
        token_segments.append(base64url_encode(raw_signature))

        # combine the header, payload, and signature into a token and return it
        token = b'.'.join(token_segments)
        return token

    def _get_verifier(self, verifying_key, signature):
        return verifying_key.verifier(signature, ec.ECDSA(hashes.SHA256()))

    def _load_verifying_key(self, verifying_key):
        if isinstance(verifying_key, EllipticCurvePublicKey):
            return verifying_key
        elif isinstance(verifying_key, (str, unicode)):
            try:
                return load_der_public_key(
                    verifying_key, backend=backend)
            except:
                try:
                    return load_pem_public_key(
                        verifying_key, backend=backend)
                except Exception as e:
                    traceback.print_exc()
                    raise ValueError('Invalid verifying key format')
        else:
            raise ValueError('Invalid verification key type')

    def _unpack_token(self, token):
        if isinstance(token, (str, unicode)):
            token = token.encode('utf-8')

        try:
            signing_input, crypto_segment = token.rsplit(b'.', 1)
            header_segment, payload_segment = signing_input.split(b'.', 1)
        except ValueError:
            raise DecodeError('Not enough segments')

        try:
            header_data = base64url_decode(header_segment)
        except (TypeError, binascii.Error):
            raise DecodeError('Invalid header padding')

        try:
            header = json.loads(header_data.decode('utf-8'))
        except ValueError as e:
            raise DecodeError('Invalid header string: %s' % e)

        if not isinstance(header, Mapping):
            raise DecodeError('Invalid header string: must be a json object')

        try:
            payload_data = base64url_decode(payload_segment)
        except (TypeError, binascii.Error):
            raise DecodeError('Invalid payload padding')

        try:
            payload = json.loads(payload_data.decode('utf-8'))
        except ValueError as e:
            raise DecodeError('Invalid payload string: %s' % e)

        try:
            signature = base64url_decode(crypto_segment)
        except (TypeError, binascii.Error):
            raise DecodeError('Invalid crypto padding')

        return (header, payload, signature, signing_input)

    def verify(self, token, verifying_key):
        # grab the token parts
        token_parts = self._unpack_token(token)
        header, payload, raw_signature, signing_input = token_parts
        # load the verifying key
        verifying_key = self._load_verifying_key(verifying_key)
        # convert the raw_signature to DER format
        der_signature = raw_to_der_signature(
            raw_signature, verifying_key.curve)
        # initialize the verifier
        verifier = self._get_verifier(verifying_key, der_signature)
        verifier.update(signing_input)
        # check to see whether the signature is valid
        try:
            verifier.verify()
        except InvalidSignature:
            # raise DecodeError('Signature verification failed')
            return False
        return True

    def decode(self, token):
        token_parts = self._unpack_token(token)
        header, payload, raw_signature, signing_input = token_parts
        token = { 
            "header": header,
            "payload": payload,
            "signature": base64url_encode(raw_signature)
        }
        return token

