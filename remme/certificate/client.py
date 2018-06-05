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
# ------------------------------------------------------------------------

import json
import datetime

from remme.protos.certificate_pb2 import CertificateStorage, \
    NewCertificatePayload, RevokeCertificatePayload, CertificateMethod
from remme.shared.basic_client import BasicClient
from remme.certificate.handler import CertificateHandler
from remme.account.handler import AccountHandler
from remme.certificate.handler import CERT_ORGANIZATION, CERT_MAX_VALIDITY


from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class CertificateClient(BasicClient):
    def __init__(self, test_helper=None):
        super().__init__(CertificateHandler, test_helper=test_helper)

    @classmethod
    def get_new_certificate_payload(self, certificate_raw, signature_rem, signature_crt, cert_signer_public_key):
        payload = NewCertificatePayload()
        payload.certificate_raw = certificate_raw
        payload.signature_rem = signature_rem
        payload.signature_crt = signature_crt
        if cert_signer_public_key:
            payload.cert_signer_public_key = cert_signer_public_key

        return payload

    @classmethod
    def get_revoke_payload(self, crt_address):
        payload = RevokeCertificatePayload()
        payload.address = crt_address

        return payload

    def process_csr(self, certificate_request, key, not_valid_before=None, not_valid_after=None):
        public_key = certificate_request.public_key()
        subject = certificate_request.subject
        issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, CERT_ORGANIZATION),
            x509.NameAttribute(NameOID.USER_ID, self.get_signer_pubkey())
        ])

        not_valid_before = not_valid_before if not_valid_before else datetime.datetime.utcnow()
        not_valid_after = not_valid_after if not_valid_after else not_valid_before + CERT_MAX_VALIDITY

        return x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        ).sign(key, hashes.SHA256(), default_backend())

    def store_certificate(self, certificate_raw, signature_rem, signature_crt, cert_signer_public_key=None):
        payload = self.get_new_certificate_payload(certificate_raw,
                                                   signature_rem,
                                                   signature_crt,
                                                   cert_signer_public_key)

        crt_address = self.make_address_from_data(certificate_raw)

        account_address = AccountHandler.make_address_from_data(self._signer.get_public_key().as_hex())
        return self._send_transaction(CertificateMethod.STORE, payload, [crt_address, account_address]), crt_address

    def revoke_certificate(self, crt_address):
        payload = self.get_revoke_payload(crt_address)
        return self._send_transaction(CertificateMethod.REVOKE, payload, [crt_address])

    def get_signer_pubkey(self):
        return self._signer.get_public_key().as_hex()

    def sign_text(self, data):
        return self._signer.sign(data.encode('utf-8'))

    def get_status(self, address):
        data = self.get_value(address)
        storage = CertificateStorage()
        storage.ParseFromString(data)
        return storage
