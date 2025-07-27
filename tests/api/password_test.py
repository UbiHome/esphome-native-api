import aioesphomeapi

import pytest

from tests.conftest import EspHomeTestServer


async def test_wrong_password(password_server: EspHomeTestServer):

    api = aioesphomeapi.APIClient("127.0.0.1", password_server.port, "wrong_password")
    with pytest.raises(aioesphomeapi.core.InvalidAuthAPIError):
        await api.connect(login=True)

    api = aioesphomeapi.APIClient("127.0.0.1", password_server.port, "password")
    await api.connect(login=True)


