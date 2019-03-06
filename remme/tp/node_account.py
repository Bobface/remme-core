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
from datetime import datetime, timedelta
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_validator.journal.batch_injector import BatchInjector
from sawtooth_validator.protobuf.batch_pb2 import (
    Batch,
    BatchHeader,
)

from remme.protos.node_account_pb2 import (
    NodeAccount,
    NodeAccountMethod,
    NodeAccountInternalTransferPayload,
    CloseMasternodePayload
)

from sawtooth_sdk.protobuf.transaction_pb2 import (
    Transaction,
    TransactionHeader,
)

from remme.protos.block_info_pb2 import BlockInfo, BlockInfoConfig
from remme.clients.block_info import BlockInfoClient, CONFIG_ADDRESS


from remme.shared.forms import (
    NodeAccountInternalTransferPayloadForm,
    CloseMasternodePayloadForm
)

from remme.settings import (
    SETTINGS_MINIMUM_STAKE,
    SETTINGS_BLOCKCHAIN_TAX,
)
from .pub_key import PUB_KEY_MAX_VALIDITY

from .basic import (
    PB_CLASS,
    PROCESSOR,
    VALIDATOR,
    BasicHandler,
    get_data,
    get_multiple_data
)
from remme.shared.utils import hash512
from remme.settings.helper import _get_setting_value
LOGGER = logging.getLogger(__name__)

FAMILY_NAME = 'node_account'
FAMILY_VERSIONS = ['0.1']


class NodeAccountHandler(BasicHandler):
    def __init__(self):
        super().__init__(FAMILY_NAME, FAMILY_VERSIONS)

    def get_state_processor(self):
        return {
            NodeAccountMethod.TRANSFER_FROM_UNFROZEN_TO_OPERATIONAL: {
                PB_CLASS: NodeAccountInternalTransferPayload,
                PROCESSOR: self._transfer_from_unfrozen_to_operational,
                VALIDATOR: NodeAccountInternalTransferPayloadForm,
            },
            NodeAccountMethod.INITIALIZE_MASTERNODE: {
                PB_CLASS: NodeAccountInternalTransferPayload,
                PROCESSOR: self._initialize_masternode,
                VALIDATOR: NodeAccountInternalTransferPayloadForm,
            },
            NodeAccountMethod.CLOSE_MASTERNODE: {
                PROCESSOR: self._close_masternode,
                PB_CLASS: CloseMasternodePayload,
                VALIDATOR: CloseMasternodePayloadForm,
            },
            NodeAccountMethod.TRANSFER_FROM_FROZEN_TO_UNFROZEN: {
                PB_CLASS: NodeAccountInternalTransferPayload,
                PROCESSOR: self._transfer_from_frozen_to_unfrozen,
                VALIDATOR: NodeAccountInternalTransferPayloadForm,
            },
        }

    @staticmethod
    def get_list_node_account_blocks(context, node_account_public_key):
        block_info_config = get_data(context, BlockInfoConfig, CONFIG_ADDRESS)
        node_account_blocks = []

        if not block_info_config:
            raise InvalidTransaction('Block config not found.')

        latest_block = get_data(
            context,
            BlockInfo,
            BlockInfoClient.create_block_address(block_info_config.latest_block),
        )
        latest_block_time = datetime.fromtimestamp(latest_block.timestamp)

        for current_block in range(block_info_config.latest_block, block_info_config.oldest_block, -1):
            current_block_addr = BlockInfoClient.create_block_address(current_block)
            current_block_info = get_data(context, BlockInfo, current_block_addr)
            # current_block_time = datetime.fromtimestamp(block_info.timestamp)

            if latest_block_time - datetime.fromtimestamp(current_block_info.timestamp) > PUB_KEY_MAX_VALIDITY:
                break

            if current_block_info.signer_public_key is node_account_public_key:
                node_account_blocks.append(current_block_info)

        return node_account_blocks

    def _get_available_pct_distribution_reward(self, context, node_account_public_key):
        node_account_address = self.make_address_from_data(node_account_public_key)
        node_account = get_data(context, NodeAccount, node_account_address)
        minimum_stake = _get_setting_value(context, SETTINGS_MINIMUM_STAKE)
        blockchain_tax = _get_setting_value(context, SETTINGS_BLOCKCHAIN_TAX)

        if node_account is None:
            raise InvalidTransaction('Invalid context or address.')

        if minimum_stake is None or not minimum_stake.isdigit():
            raise InvalidTransaction('Wrong minimum stake address.')

        if blockchain_tax is None or not blockchain_tax.isdigit():
            raise InvalidTransaction('Wrong blockchain tax address.')

        # node_reputation = node_account.reputation.frozen + node_account.reputation.unfrozen
        minimum_stake = int(minimum_stake)
        max_reward = 1 - int(blockchain_tax)
        min_reward = .45
        defrost_acceleration = 10

        if node_account.reputation.frozen < minimum_stake:
            raise InvalidTransaction('Frozen balance is lower than the minimum stake.')

        if node_account.reputation.frozen >= defrost_acceleration * minimum_stake:
            return max_reward

        reward_span = (max_reward - min_reward) / (defrost_acceleration - 1)
        quantity_stakes = (node_account.reputation.frozen - minimum_stake) / minimum_stake

        available_pct_distribution_reward = reward_span * quantity_stakes + min_reward

        return available_pct_distribution_reward

    def _get_available_amount_defrosting_tokens_to_unfrozen(self, context, node_account_public_key):
        node_account_address = self.make_address_from_data(node_account_public_key)
        node_account = get_data(context, NodeAccount, node_account_address)
        minimum_stake = _get_setting_value(context, SETTINGS_MINIMUM_STAKE)
        blockchain_tax = _get_setting_value(context, SETTINGS_BLOCKCHAIN_TAX)

        if node_account is None:
            raise InvalidTransaction('Invalid context or address.')

        if minimum_stake is None or not minimum_stake.isdigit():
            raise InvalidTransaction('Wrong minimum stake address.')

        if blockchain_tax is None or not blockchain_tax.isdigit():
            raise InvalidTransaction('Wrong blockchain tax address.')

        minimum_stake = int(minimum_stake)
        if node_account.reputation.frozen < minimum_stake:
            raise InvalidTransaction('Frozen balance is lower than the minimum stake.')

        max_reward = 1 - int(blockchain_tax)

        block_price = 1000  # Replace by real block price

        pct_distribution_reward = self._get_available_pct_distribution_reward(context, node_account_public_key)

        node_account_blocks = self.get_list_node_account_blocks(context, node_account_public_key)

        amount_defrosting_tokens_to_unfrozen = 0
        for block in node_account_blocks:
            time_rate = block.timestamp / PUB_KEY_MAX_VALIDITY

            amount_defrosting_tokens_to_unfrozen += (max_reward - pct_distribution_reward) * time_rate * block_price

        return amount_defrosting_tokens_to_unfrozen

    def _initialize_masternode(self, context, node_account_public_key, internal_transfer_payload):
        node_account_address = self.make_address_from_data(node_account_public_key)

        node_account = get_data(context, NodeAccount, node_account_address)

        if node_account is None:
            node_account = NodeAccount()

        if node_account.node_state != NodeAccount.NEW:
            raise InvalidTransaction('Masternode is already opened or closed.')

        if node_account.balance < internal_transfer_payload.value:
            raise InvalidTransaction('Insufficient amount of tokens on operational account.')

        minimum_stake = _get_setting_value(context, SETTINGS_MINIMUM_STAKE)
        if minimum_stake is None or not minimum_stake.isdigit():
            raise InvalidTransaction('remme.settings.minimum_stake is malformed. Should be not negative integer.')
        minimum_stake = int(minimum_stake)

        if internal_transfer_payload.value < minimum_stake:
            raise InvalidTransaction('Initial stake is too low.')

        node_account.node_state = NodeAccount.OPENED

        node_account.balance -= internal_transfer_payload.value

        unfrozen_part = internal_transfer_payload.value - minimum_stake
        node_account.reputation.frozen += minimum_stake
        node_account.reputation.unfrozen += unfrozen_part

        return {
            node_account_address: node_account,
        }

    def _close_masternode(self, context, node_account_public_key, payload):
        node_account_address = self.make_address_from_data(node_account_public_key)

        node_account = get_data(context, NodeAccount, node_account_address)

        if node_account is None:
            raise InvalidTransaction('Invalid context or address.')

        if node_account.node_state != NodeAccount.OPENED:
            raise InvalidTransaction('Masternode is not opened or has been closed.')

        node_account.node_state = NodeAccount.CLOSED

        node_account.balance += node_account.reputation.frozen
        node_account.balance += node_account.reputation.unfrozen

        node_account.reputation.frozen = 0
        node_account.reputation.unfrozen = 0

        return {
            node_account_address: node_account,
        }

    def _transfer_from_unfrozen_to_operational(self, context, node_account_public_key, internal_transfer_payload):

        node_account_address = self.make_address_from_data(node_account_public_key)

        node_account = get_data(context, NodeAccount, node_account_address)

        if node_account is None:
            raise InvalidTransaction('Invalid context or address.')

        if node_account.reputation.unfrozen < internal_transfer_payload.value:
            raise InvalidTransaction('Insufficient amount of tokens on unfrozen account.')

        node_account.reputation.unfrozen -= internal_transfer_payload.value
        node_account.balance += internal_transfer_payload.value

        return {
            node_account_address: node_account,
        }

    def _transfer_from_frozen_to_unfrozen(self, context, node_account_public_key, internal_transfer_payload):
        node_account_address = self.make_address_from_data(node_account_public_key)
        node_account = get_data(context, NodeAccount, node_account_address)
        minimum_stake = _get_setting_value(context, SETTINGS_MINIMUM_STAKE)

        if node_account is None:
            raise InvalidTransaction('Invalid context or address.')

        if minimum_stake is None or not minimum_stake.isdigit():
            raise InvalidTransaction('Wrong minimum stake address.')

        minimum_stake = int(minimum_stake)

        if node_account.reputation.frozen < minimum_stake:
            raise InvalidTransaction('Frozen balance is lower than the minimum stake.')

        if node_account.reputation.frozen - internal_transfer_payload.value < minimum_stake:
            raise InvalidTransaction('Frozen balance after transfer lower than the minimum stake.')

        node_account.reputation.frozen -= internal_transfer_payload.value
        node_account.reputation.unfrozen += internal_transfer_payload.value

        return {
            node_account_address: node_account,
        }

    class NodeAccountInjector(BatchInjector):
        """Inject ObligatoryPayment transaction at the beginning of blocks."""

        def __init__(self, state_view_factory, signer):
            self._state_view_factory = state_view_factory
            self._signer = signer

        def create_batch(self):
            payload = NodeAccountInternalTransferPayload().SerializeToString()
            public_key = self._signer.get_public_key().as_hex()

            block_signer_address = NodeAccountHandler().make_address_from_data(data=public_key)

            INPUTS = OUTPUTS = [
                block_signer_address
            ]

            header = TransactionHeader(
                signer_public_key=public_key,
                family_name=FAMILY_NAME,
                family_version=FAMILY_VERSIONS[0],
                inputs=INPUTS,
                outputs=OUTPUTS,
                dependencies=[],
                payload_sha512=hash512(payload).hexdigest(),
                batcher_public_key=public_key,
            ).SerializeToString()

            transaction_signature = self._signer.sign(header)

            transaction = Transaction(
                header=header,
                payload=payload,
                header_signature=transaction_signature,
            )

            header = BatchHeader(
                signer_public_key=public_key,
                transaction_ids=[transaction_signature],
            ).SerializeToString()

            batch_signature = self._signer.sign(header)

            return Batch(
                header=header,
                transactions=[transaction],
                header_signature=batch_signature,
            )
