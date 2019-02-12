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

from remme.clients.pub_key import PubKeyClient
from remme.shared.forms import ProtoForm

from .utils import validate_params


__all__ = (
    'get_node_info',
    'fetch_peers',
)

logger = logging.getLogger(__name__)


@validate_params(ProtoForm)
async def get_node_info(request):
    client = PubKeyClient()
    data = await client.fetch_peers()
    return {'is_synced': True, 'peer_count': len(data['data'])}


@validate_params(ProtoForm)
async def fetch_peers(request):
    client = PubKeyClient()
    return await client.fetch_peers()
