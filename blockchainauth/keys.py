#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    ~~~~~
    :copyright: (c) 2015 by Halfmoon Labs, Inc.
    :license: MIT, see LICENSE for more details.
"""

from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key, load_pem_private_key, load_der_public_key,
    load_pem_public_key
)
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey
)


def load_signing_key(signing_key):
    if isinstance(signing_key, EllipticCurvePrivateKey):
        return signing_key
    elif isinstance(signing_key, (str, unicode)):
        invalid_strings = [b'-----BEGIN PUBLIC KEY-----']
        invalid_string_matches = [
            string_value in signing_key
            for string_value in invalid_strings
        ]
        if any(invalid_string_matches):
            raise ValueError(
                'Signing key must be a private key, not a public key.')

        try:
            return load_der_private_key(
                signing_key, password=None, backend=backend)
        except:
            try:
                return load_pem_private_key(
                    signing_key, password=None, backend=backend)
            except Exception as e:
                raise ValueError(
                    'Signing key must be a valid private key PEM or DER.')
    else:
        raise ValueError('Signing key must be in string or unicode format.')
