"""
Provide tests for batch event handler implementation.
"""
import pytest
from aiohttp_json_rpc.exceptions import RpcInvalidParamsError

from remme.rpc_api.event._handlers import BatchEventHandler

VALID_BATCH_ID = 'b2e08b7fd6e4568db5c3f8ed25a00f610ac9f3a1fec911c026cadccb3a5a1bd4' \
                 '79da9f4e49b4eb9d28f17fefb925e64b447ab1c694e73a8871ab3120f09dd332'

VALID_BATCH_ID_LENGTH = len(VALID_BATCH_ID)

batch_event_handler = BatchEventHandler()


def test_validate_batch_identifier():
    """
    Case: validate valid batch identifier.
    Expect: identifier as dictionary with appropriate key is returned.
    """
    expected_result = {
        'id': VALID_BATCH_ID,
    }

    result = batch_event_handler.validate(msg_id=None, params={
        'id': VALID_BATCH_ID
    })

    assert expected_result == result


def test_validate_batch_identifier_no_identifier():
    """
    Case: validate not specified batch identifier.
    Expect: RPC invalid params error is raised with invalid params error message.
    """
    with pytest.raises(RpcInvalidParamsError) as error:
        batch_event_handler.validate(msg_id=None, params={})

    assert 'Invalid params' == str(error.value)


@pytest.mark.parametrize(
    'invalid_batch_id',
    [
        pytest.param('a' * (VALID_BATCH_ID_LENGTH - 1), id='batch identifier invalid length'),
        pytest.param('InvalidBatchIdentifier', id='text instead batch identifier'),
        pytest.param('su' * (VALID_BATCH_ID_LENGTH // 2), id='not passed batch identifier regexp'),
    ],
)
def test_validate_batch_invalid_identifier(invalid_batch_id):
    """
    Case: validate invalid batch identifier.
    Expect: RPC invalid params error is raised with invalid params error message.
    """
    with pytest.raises(RpcInvalidParamsError) as error:
        batch_event_handler.validate(msg_id=None, params={
            'id': invalid_batch_id,
        })

    assert 'Invalid params' == str(error.value)
