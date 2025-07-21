
from asyncio import sleep
from unittest.mock import Mock
import aioesphomeapi


async def test_encrypted_server():  # test_server: TestServer):
    """test encrypted server"""

    api = aioesphomeapi.APIClient("127.0.0.1", 7001, None, noise_psk="px7tsbK3C7bpXHr2OevEV2ZMg/FrNBw2+O2pNPbedtA=")
    # api = aioesphomeapi.APIClient("127.0.0.1", test_server.port, "")
    await api.connect(login=False)

    # Test API Hello
    assert api.api_version.major == 1
    assert api.api_version.minor == 42
    assert api.log_name == "test_device @ 127.0.0.1"

    # Test Device Details
    device_info = await api.device_info()
    assert device_info.name == "test_device"
    assert device_info.friendly_name == "friendly_test_device"
    assert device_info.bluetooth_mac_address == "B0:00:00:00:00:00"
    assert device_info.mac_address == "00:00:00:00:00:01"
    assert device_info.manufacturer == "Test Inc."
    assert device_info.model == "Test Model"
    assert device_info.suggested_area == "Test Area"

    entities, services = await api.list_entities_services()
    print("entities", entities, services)

    assert len(entities) == 0, entities

    api.disconnect()
