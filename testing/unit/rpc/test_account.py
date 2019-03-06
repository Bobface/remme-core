import pytest
from aiohttp_json_rpc.exceptions import RpcInvalidParamsError

from remme.rpc_api.account import get_public_keys_list
from testing.utils._async import return_async_value


@pytest.mark.asyncio
async def test_get_public_keys_list(mocker, request_):
    """
    Case: get public keys list.
    Expect: list with addresses.
    """
    public_key_address = '112007081971dec92814033df35188ce17c740d5e58d7632c9528b61a88a4b4cde51e1'
    request_.params = public_key_address

    expected_result = []

    mock_get_block_info = mocker.patch('remme.clients.account.AccountClient.get_pub_keys')
    mock_get_block_info.return_value = return_async_value(expected_result)

    result = await get_public_keys_list(request_)

    assert expected_result == result


@pytest.mark.asyncio
@pytest.mark.parametrize('public_key_address', [
        '12345', 12345, True,
    ],
)
async def test_get_public_keys_list_with_invalid_address(request_, public_key_address):
    """
    Case: get public keys list with invalid address.
    Expect: address is not of a blockchain token type error message.
    """
    request_.params = public_key_address

    with pytest.raises(RpcInvalidParamsError) as error:
        await get_public_keys_list(request_)

    assert 'Address is not of a blockchain token type.' == error.value.message


@pytest.mark.asyncio
async def test_get_public_keys_list_without_address(request_):
    """
    Case: get public keys list without address.
    Expect: missed address error message.
    """
    public_key_address = None
    request_.params = public_key_address

    with pytest.raises(RpcInvalidParamsError) as error:
        await get_public_keys_list(request_)

    assert 'Missed address.' == error.value.message
