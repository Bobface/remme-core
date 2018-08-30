import hashlib
import json

from google.protobuf.json_format import MessageToDict, MessageToJson
from sawtooth_signing import create_context
from web3 import Web3


def generate_random_key():
    return create_context('secp256k1').new_random_private_key().as_hex()


# kecak256
def hash256(data):
    return hashlib.sha3_256(data.encode('utf-8') if isinstance(data, str) else data).hexdigest()


def hash512(data):
    return hashlib.sha512(data.encode('utf-8') if isinstance(data, str) else data).hexdigest()


def web3_hash(data):
    return str(Web3.toHex(Web3.sha3(hexstr=data)))[2:]


def from_proto_to_dict(proto_obj):
    return MessageToDict(proto_obj, preserving_proto_field_name=True, including_default_value_fields=True)


class AttrDict(dict):
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self


def get_batch_id(response_dict):
    link = response_dict['link']
    batch_id = link.split('id=')[1]
    return {'batch_id': batch_id}


def message_to_dict(message):
    return MessageToDict(
        message,
        including_default_value_fields=True,
        preserving_proto_field_name=True)

class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]
