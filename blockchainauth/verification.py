#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    ~~~~~
    :copyright: (c) 2017 by Stanislav Pankratov
    :license: MIT, see LICENSE for more details.
"""

import requests
import requests.exceptions
import time
import traceback
from pybitcoin import BitcoinPublicKey
from blockchainauth.dids import get_address_from_did

LOCALHOST_CORE_API = 'http://localhost:6270'
EXTERNAL_CORE_API = 'https://core.blockstack.org'
NAME_LOOKUP_URL = '/v1/names/'


def do_signatures_match_public_keys(token, tokenizer, decoded_token):
    # extract the public key from the token
    try:
        payload = decoded_token['payload']
        if not payload['public_keys']:
            return True
        if len(payload['public_keys']) != 1:
            raise NotImplementedError('Multiple public keys are not supported')
        public_key = BitcoinPublicKey(str(payload['public_keys'][0]))
    except KeyError:
        traceback.print_exc()
        return False

    # return whether the token is verified/valid
    return tokenizer.verify(token, public_key.to_pem())


def do_public_keys_match_issuer(token, tokenizer, decoded_token):
    # extract the public key from the token
    try:
        payload = decoded_token['payload']
        if not payload['public_keys']:
            return not payload.get('iss', None)
        if len(payload['public_keys']) != 1:
            raise NotImplementedError('Multiple public keys are not supported')
        address_from_pub_key = BitcoinPublicKey(str(payload['public_keys'][0])).address()
        address_from_iss = get_address_from_did(payload['iss'])
        return address_from_pub_key == address_from_iss
    except (KeyError, ValueError):
        traceback.print_exc()
        return False


def do_public_keys_match_username(token, tokenizer, decoded_token):
    try:
        payload = decoded_token['payload']
    except KeyError:
        traceback.print_exc()
        return False

    if not payload.get('username', None):
        return True

    username = payload['username']

    # get publicly available address and address from payload
    # first try from localhost
    url = LOCALHOST_CORE_API + NAME_LOOKUP_URL + username
    try:
        response = requests.get(url).json()
    except (requests.exceptions.RequestException, ValueError):
        # ValueError for non-json responses
        response = None

    # if failed try from public Core API
    if not response:
        url = EXTERNAL_CORE_API + NAME_LOOKUP_URL + username
        try:
            response = requests.get(url).json()
        except (requests.exceptions.RequestException, ValueError):
            # ValueError for non-json responses
            response = None

    if not response:
        return False

    try:
        address_from_issuer = get_address_from_did(payload.get('iss', ''))
    except ValueError:
        traceback.print_exc()
        return False

    return 'address' in response and address_from_issuer and \
           response['address'] == address_from_issuer


def is_issuance_date_valid(token, tokenizer, decoded_token):
    # Issued At value must be lesser than current time
    try:
        return time.time() > float(decoded_token['payload']['iat'])
    except (KeyError, ValueError):
        traceback.print_exc()
        return False


def is_expiration_date_valid(token, tokenizer, decoded_token):
    # Expires At value must be lesser than current time
    try:
        return time.time() < float(decoded_token['payload']['exp'])
    except (KeyError, ValueError):
        traceback.print_exc()
        return False
