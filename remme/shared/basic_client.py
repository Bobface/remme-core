# Copyright 2018 REMME
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------
import logging
import base64
import time
import json

import requests
import yaml
from sawtooth_sdk.protobuf.batch_pb2 import Batch
from sawtooth_sdk.protobuf.batch_pb2 import BatchHeader
from sawtooth_sdk.protobuf.batch_pb2 import BatchList
from sawtooth_sdk.protobuf.transaction_pb2 import Transaction
from sawtooth_sdk.protobuf.transaction_pb2 import TransactionHeader
from sawtooth_signing import CryptoFactory
from sawtooth_signing import ParseError
from sawtooth_signing import create_context
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey

from remme.protos.transaction_pb2 import TransactionPayload
from remme.settings import REST_API_URL, PRIV_KEY_FILE
from remme.shared.exceptions import ClientException
from remme.shared.exceptions import KeyNotFound
from remme.shared.utils import hash512
from remme.account.handler import AccountHandler, is_address


LOGGER = logging.getLogger(__name__)


class BasicClient:

    def __init__(self, family_handler, test_helper=None, keyfile=PRIV_KEY_FILE):
        self.url = REST_API_URL
        self._family_handler = family_handler
        self.test_helper = test_helper

        try:
            self._signer = self.get_signer_priv_key_from_file(keyfile)
        except ClientException as e:
            LOGGER.warn('Could not set up signer from file, detailed: %s', e)
            self._signer = self.generate_signer(keyfile)

    @staticmethod
    def get_signer_priv_key_from_file(keyfile):
        try:
            with open(keyfile) as fd:
                private_key_str = fd.read().strip()
        except OSError as err:
            raise ClientException(
                'Failed to read private key: {}'.format(str(err)))

        try:
            private_key = Secp256k1PrivateKey.from_hex(private_key_str)
        except ParseError as e:
            raise ClientException(
                'Unable to load private key: {}'.format(str(e)))

        context = create_context('secp256k1')
        return CryptoFactory(context).new_signer(private_key)

    @staticmethod
    def generate_signer(keyfile=None):
        context = create_context('secp256k1')
        private_key = context.new_random_private_key()
        if keyfile:
            try:
                with open(keyfile, 'w') as fd:
                    fd.write(private_key.as_hex())
            except OSError as err:
                raise ClientException('Failed to write private key: {0}'.format(err))
        return CryptoFactory(context).new_signer(private_key)

    def make_address(self, suffix):
        return self._family_handler.make_address(suffix)

    def make_address_from_data(self, data):
        return self._family_handler.make_address_from_data(data)

    def is_address(self, address):
        return self._family_handler.is_address(address)

    def get_value(self, key):
        result = self._send_request("state/{}".format(key))
        return base64.b64decode(json.loads(result)['data'])

    def get_signer(self):
        return self._signer

    def get_public_key(self):
        return self.get_signer().get_public_key().as_hex()

    def _get_status(self, batch_id, wait):
        try:
            result = self._send_request(
                'batch_statuses?id={}&wait={}'.format(batch_id, wait),)
            return yaml.safe_load(result)['data'][0]['status']
        except BaseException as err:
            raise ClientException(err)

    def _get_prefix(self):
        return self._family_handler.namespaces[-1]

    def _get_address(self, pub_key):
        if len(pub_key) > 64:
            raise ClientException("Wrong pub_key size: {}".format(pub_key))
        prefix = self._get_prefix()
        return prefix + pub_key

    def _send_request(self, suffix, data=None, content_type=None):
        url = f"{self.url}/{suffix}"

        if not url.startswith("http://"):
            url = f"http://{url}"

        headers = {}

        if content_type is not None:
            headers['Content-Type'] = content_type

        try:
            if data is not None:
                result = requests.post(url, headers=headers, data=data)
            else:
                result = requests.get(url, headers=headers)

            if result.status_code == 404:
                raise KeyNotFound("404")

            elif not result.ok:
                raise ClientException("Error {}: {}".format(
                    result.status_code, result.reason))

        except requests.ConnectionError as err:
            raise ClientException(
                'Failed to connect to REST API: {}'.format(err))

        batch_response = json.loads(result.text)
        link = batch_response['link']
        batch_id = link.split('id=')[1]

        return {'batch_id': batch_id}

    def make_batch_list(self, payload_pb, addresses_input_output):
        payload = payload_pb.SerializeToString()
        signer = self._signer
        header = TransactionHeader(
            signer_public_key=signer.get_public_key().as_hex(),
            family_name=self._family_handler.family_name,
            family_version=self._family_handler.family_versions[-1],
            inputs=addresses_input_output,
            outputs=addresses_input_output,
            dependencies=[],
            payload_sha512=hash512(payload),
            batcher_public_key=signer.get_public_key().as_hex(),
            nonce=time.time().hex().encode()
        ).SerializeToString()

        signature = signer.sign(header)

        transaction = Transaction(
            header=header,
            payload=payload,
            header_signature=signature
        )

        return self._sign_batch_list(signer, [transaction])

    def set_signer(self, new_signer):
        self._signer = new_signer

    def get_user_address(self):
        return AccountHandler.make_address_from_data(self._signer.get_public_key().as_hex())

    def _send_transaction(self, method, data_pb, addresses_input_output):
        '''
           Signs and sends transaction to the network using rest-api.

           :param str method: The method (defined in proto) for Transaction Processor to process the request.
           :param dict data: Dictionary that is required by TP to process the transaction.
           :param str addresses_input_output: list of addresses(keys) for which to get and save state.
        '''
        # forward transaction to test helper
        if self.test_helper:
            self.test_helper.send_transaction(method, data_pb, addresses_input_output)
            return

        payload = TransactionPayload()
        payload.method = method
        payload.data = data_pb.SerializeToString()

        for address in addresses_input_output:
            if not is_address(address):
                raise ClientException('one of addresses_input_output {} is not an address'.format(addresses_input_output))

        batch_list = self.make_batch_list(payload, addresses_input_output)
        return self._send_request(
            "batches", batch_list.SerializeToString(),
            'application/octet-stream',
        )

    def _send_raw_transaction(self, transaction_pb):
        batch_list = self._sign_batch_list(self._signer, [transaction_pb])

        return self._send_request(
            "batches", batch_list.SerializeToString(),
            'application/octet-stream',
        )

    def _sign_batch_list(self, signer, transactions):
        transaction_signatures = [t.header_signature for t in transactions]

        header = BatchHeader(
            signer_public_key=signer.get_public_key().as_hex(),
            transaction_ids=transaction_signatures
        ).SerializeToString()

        signature = signer.sign(header)

        batch = Batch(
            header=header,
            transactions=transactions,
            header_signature=signature)
        return BatchList(batches=[batch])
