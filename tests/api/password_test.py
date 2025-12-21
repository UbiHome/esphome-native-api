import aioesphomeapi

import pytest

from tests.conftest import EspHomeTestServer

@pytest.mark.skip("Skip because of https://github.com/esphome/aioesphomeapi/issues/1463")
async def test_wrong_password(password_server: EspHomeTestServer):
    """
    Test that wrong_password returns invalid auth error
    and correct password allows access to device data
    """

    api = aioesphomeapi.APIClient("127.0.0.1", password_server.port, "wrong_password")
    with pytest.raises(aioesphomeapi.core.InvalidAuthAPIError):
        await api.connect(login=True)

    api = aioesphomeapi.APIClient("127.0.0.1", password_server.port, "password")
    await api.connect(login=True)

    device_info = await api.device_info()
    assert device_info.name == "test_device"

async def test_wrong_password_gets_no_data(password_server: EspHomeTestServer):
    """
    Test that a wrong password does not allow access to device data
    """

    api = aioesphomeapi.APIClient("127.0.0.1", password_server.port, "wrong_password")
    # with pytest.raises(aioesphomeapi.core.InvalidAuthAPIError):
    await api.connect(login=False)

    # Test API Hello
    assert api.api_version.major == 1
    assert api.api_version.minor == 10
    assert api.log_name == "test_device @ 127.0.0.1"

    # Test Closes connection as unauthorized request
    with pytest.raises(aioesphomeapi.core.SocketClosedAPIError):
        await api.device_info()
