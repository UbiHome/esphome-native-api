"""Error-path tests: misconfigured or misbehaving clients must be rejected
cleanly, and the server must keep serving well-behaved clients afterwards.

The encrypted-server rejection cases (wrong key, plaintext client) are already
covered in encrypted_server_test.py."""

import asyncio

import aioesphomeapi
import pytest

from tests_e2e.conftest import EspHomeTestServer

# A valid 32-byte base64 key that is not the server's key.
WRONG_NOISE_PSK = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="


async def assert_connect_ok(server: EspHomeTestServer, noise_psk: str | None = None):
    """A well-behaved client can connect and talk to the server."""
    api = aioesphomeapi.APIClient("127.0.0.1", server.port, "", noise_psk=noise_psk)
    await api.connect(login=False)
    device_info = await api.device_info()
    assert device_info.name == "test_device"
    await api.disconnect()


async def test_encrypted_client_is_rejected_by_plaintext_server(
    test_server: EspHomeTestServer,
):
    api = aioesphomeapi.APIClient(
        "127.0.0.1", test_server.port, "", noise_psk=WRONG_NOISE_PSK
    )
    with pytest.raises(aioesphomeapi.EncryptionPlaintextAPIError):
        await api.connect(login=False)

    await assert_connect_ok(test_server)


async def test_server_survives_client_with_invalid_marker_byte(
    test_server: EspHomeTestServer,
):
    _, writer = await asyncio.open_connection("127.0.0.1", test_server.port)
    writer.write(b"\x42")
    await writer.drain()
    writer.close()
    await writer.wait_closed()

    await assert_connect_ok(test_server)


async def test_server_survives_client_that_sends_no_data(
    test_server: EspHomeTestServer,
):
    _, writer = await asyncio.open_connection("127.0.0.1", test_server.port)
    writer.close()
    await writer.wait_closed()

    await assert_connect_ok(test_server)
