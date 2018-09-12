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
import logging

from google.protobuf.text_format import ParseError
from sawtooth_processor_test.message_factory import MessageFactory
from sawtooth_sdk.processor.exceptions import InternalError, InvalidTransaction
from remme.protos.transaction_pb2 import TransactionPayload
from remme.protos.account_pb2 import TransferPayload, Account
from remme.shared.utils import hash512, Singleton
from remme.settings import GENESIS_ADDRESS, ZERO_ADDRESS


LOGGER = logging.getLogger(__name__)


def is_address(address):
    try:
        assert isinstance(address, str)
        assert len(address) == 70
        int(address, 16)
        return True
    except (AssertionError, ValueError):
        return False


def get_data(context, pb_class, address):
    raw_data = context.get_state([address])
    LOGGER.debug(f'Raw data: {raw_data}')
    if raw_data:
        try:
            data = pb_class()
            data.ParseFromString(raw_data[0].data)
            return data
        except IndexError:
            return None
        except ParseError:
            raise InternalError('Failed to deserialize data')
    else:
        return None


def get_multiple_data(context, data):
    raw_data = context.get_state([el[0] for el in data])
    raw_data = {entry.address: entry.data for entry in raw_data}
    datas = []
    for address, pb_class in data:
        try:
            data = pb_class()
            data.ParseFromString(raw_data[address])
            datas.append(data)
        except Exception:
            datas.append(None)
    return datas


class BasicHandler(metaclass=Singleton):
    """
        BasicHandler contains shared logic...
    """

    def __init__(self, name, versions):
        self._family_name = name
        self._family_versions = versions
        self._prefix = hash512(self._family_name)[:6]

    @property
    def family_name(self):
        """
           BasicHandler contains shared logic...
        """
        return self._family_name

    @property
    def family_versions(self):
        return self._family_versions

    @property
    def namespaces(self):
        return [self._prefix]

    def get_state_processor(self):
        raise InternalError('No implementation for `get_state_processor`')

    def get_message_factory(self, signer=None):
        return MessageFactory(
            family_name=self.family_name,
            family_version=self.family_versions[-1],
            namespace=self.namespaces[-1],
            signer=signer
        )

    def is_handler_address(self, address):
        return is_address(address) and address.startswith(self._prefix)

    def apply(self, transaction, context):
        transaction_payload = TransactionPayload()
        transaction_payload.ParseFromString(transaction.payload)

        state_processor = self.get_state_processor()
        try:
            data_pb = state_processor[transaction_payload.method]['pb_class']()
            data_pb.ParseFromString(transaction_payload.data)
            processor = state_processor[transaction_payload.method]['processor']
            updated_state = processor(context, transaction.header.signer_public_key, data_pb)
        except KeyError:
            raise InvalidTransaction('Unknown value {} for the pub_key operation type.'.
                                     format(int(transaction_payload.method)))
        except ParseError:
            raise InvalidTransaction('Cannot decode transaction payload')
        print(self._family_name)
        addresses = context.set_state({k: v.SerializeToString()
                                       for k, v in updated_state.items()})
        if len(addresses) < len(updated_state):
            raise InternalError('Failed to update all of states. Updated: {}. '
                                'Full list of states to update: {}.'
                                .format(addresses, updated_state.keys()))

    def make_address(self, appendix):
        address = self._prefix + appendix
        if not is_address(address):
            raise InternalError('{} is not a valid address'.format(address))
        return address

    def make_address_from_data(self, data):
        appendix = hash512(data)[:64]
        return self.make_address(appendix)

    @classmethod
    def create_transfer(cls, context, address_from, address_to, amount):
        transfer_payload = TransferPayload(address_to=address_to, value=amount)
        return cls() \
            ._transfer_from_address(context, address_from, transfer_payload)

    def _transfer_from_address(self, context, address, transfer_payload):
        signer_key = address

        if not transfer_payload.value:
            raise InvalidTransaction("Could not transfer with zero amount")

        signer_account, receiver_account = get_multiple_data(context, [
            (signer_key, Account),
            (transfer_payload.address_to, Account)
        ])

        # TODO transfer from genesis address using SETTINGS_KEY_GENESIS_OWNERS
        # list of allowed addresses(0x0)
        # genesis_members_str = _get_setting_value(context,
        #                                          SETTINGS_KEY_GENESIS_OWNERS)
        # if not genesis_members_str:
        #     raise InvalidTransaction('REMchain is not configured '
        #                              'to process genesis transfers.')
        #
        # genesis_members_list = genesis_members_str.split()

        if not receiver_account:
            receiver_account = Account()
        if not signer_account:
            signer_account = Account()

        if signer_account.balance < transfer_payload.value:
            raise InvalidTransaction(
                "Not enough transferable balance. Sender's current balance: "
                f"{signer_account.balance}")

        receiver_account.balance += transfer_payload.value
        signer_account.balance -= transfer_payload.value

        LOGGER.info(f'Transferred {transfer_payload.value} tokens from '
                    f'{signer_key} to {transfer_payload.address_to}')

        return {
            signer_key: signer_account,
            transfer_payload.address_to: receiver_account
        }
