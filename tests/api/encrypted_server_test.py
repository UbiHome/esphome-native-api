from asyncio import sleep
import logging
from unittest.mock import AsyncMock, Mock
import aioesphomeapi
from aioesphomeapi.reconnect_logic import ReconnectLogic, ReconnectLogicState

import pytest

from tests.conftest import EspHomeTestServer


async def test_encrypted_server(encrypted_server: EspHomeTestServer):
    """test encrypted server"""

    api = aioesphomeapi.APIClient(
        "127.0.0.1",
        encrypted_server.port,
        None,
        noise_psk=encrypted_server.noise_psk,
    )
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

    # List all entities of the device (order should be alphabetical)
    entities, services = await api.list_entities_services()
    print("entities", entities, services)

    assert len(entities) == 5, entities
    binary_sensor = next(
        (e for e in entities if isinstance(e, aioesphomeapi.BinarySensorInfo))
    )
    light = next((e for e in entities if isinstance(e, aioesphomeapi.LightInfo)))
    button = next((e for e in entities if isinstance(e, aioesphomeapi.ButtonInfo)))
    switch = next((e for e in entities if isinstance(e, aioesphomeapi.SwitchInfo)))
    sensor = next((e for e in entities if isinstance(e, aioesphomeapi.SensorInfo)))

    assert isinstance(binary_sensor, aioesphomeapi.BinarySensorInfo)
    assert binary_sensor.name == "test_binary_sensor"
    assert binary_sensor.key == 3
    assert binary_sensor.icon == "mdi:test-binary-sensor-icon"
    assert binary_sensor.device_class == "test_binary_sensor_device_class"
    assert binary_sensor.disabled_by_default is False
    assert binary_sensor.entity_category == aioesphomeapi.EntityCategory.NONE
    assert binary_sensor.object_id == "test_binary_sensor_object_id"

    assert isinstance(button, aioesphomeapi.ButtonInfo)
    assert button.name == "test_button"
    assert button.key == 0
    assert button.icon == "mdi:test-button-icon"
    assert button.device_class == "test_button_device_class"
    assert button.disabled_by_default is False
    assert button.entity_category == aioesphomeapi.EntityCategory.NONE
    assert button.object_id == "test_button_object_id"

    assert isinstance(switch, aioesphomeapi.SwitchInfo)
    assert switch.name == "test_switch"
    assert switch.key == 1
    assert switch.icon == "mdi:test-switch-icon"
    assert switch.device_class == "test_switch_device_class"
    assert switch.disabled_by_default is False
    assert switch.entity_category == aioesphomeapi.EntityCategory.NONE
    assert switch.object_id == "test_switch_object_id"

    assert isinstance(light, aioesphomeapi.LightInfo)
    assert light.name == "test_light"
    assert light.key == 4
    assert light.icon == "mdi:test-light-icon"
    assert light.disabled_by_default is False
    assert light.entity_category == aioesphomeapi.EntityCategory.NONE
    assert light.object_id == "test_light_object_id"

    assert isinstance(sensor, aioesphomeapi.SensorInfo)
    assert sensor.name == "test_sensor"
    assert sensor.key == 2
    assert sensor.icon == "mdi:test-sensor-icon"
    assert sensor.disabled_by_default is False
    assert sensor.entity_category == aioesphomeapi.EntityCategory.NONE
    assert sensor.object_id == "test_sensor_object_id"

    mock = Mock()
    # # Subscribe to the state changes
    api.subscribe_states(mock)

    # State update should be send back
    while not mock.called:
        await sleep(0.1)
    state = mock.call_args.args[0]
    assert isinstance(state, aioesphomeapi.SensorState)
    assert state.state == 25.0
    mock.reset_mock()

    await api.disconnect()


async def test_do_not_allow_unauthenticated(encrypted_server: EspHomeTestServer):
    """An encrypted server should not allow unauthenticated access"""

    api = aioesphomeapi.APIClient(
        "127.0.0.1",
        encrypted_server.port,
        "password"
    )

    with pytest.raises(aioesphomeapi.core.RequiresEncryptionAPIError):
        await api.connect(login=False)


async def test_require_encryption_error(encrypted_server: EspHomeTestServer):
    """An encrypted server should not allow unauthenticated access"""

    api = aioesphomeapi.APIClient("127.0.0.1", encrypted_server.port, None)
    
    with pytest.raises(aioesphomeapi.core.RequiresEncryptionAPIError):
        await api.connect(login=False)


async def test_do_not_allow_password_authentication(encrypted_server: EspHomeTestServer):
    """An encrypted server should not allow password authentication"""

    api = aioesphomeapi.APIClient(
        "127.0.0.1",
        encrypted_server.port,
        "password"
    )

    # Test Closes connection as unauthorized request
    with pytest.raises(aioesphomeapi.core.RequiresEncryptionAPIError):
        await api.connect(login=True)


async def test_do_not_allow_wrong_key(encrypted_server: EspHomeTestServer):
    api = aioesphomeapi.APIClient(
        "127.0.0.1",
        encrypted_server.port,
        None,
        noise_psk="RcaiIwmN008EoAE7KkN2qCXic+hm540EhLvD30EnhhE=",
    )
    with pytest.raises(aioesphomeapi.core.InvalidEncryptionKeyAPIError):
        await api.connect(login=False)


async def test_encrypted_server_with_login(encrypted_server: EspHomeTestServer):
    """test encrypted server"""

    api = aioesphomeapi.APIClient(
        "127.0.0.1",
        encrypted_server.port,
        None,
        noise_psk=encrypted_server.noise_psk,
    )
    await api.connect(login=True)

    # Test API Hello
    assert api.api_version.major == 1
    assert api.api_version.minor == 42
    assert api.log_name == "test_device @ 127.0.0.1"

    await api.disconnect()


async def test_encrypted_server_reconnect(encrypted_server: EspHomeTestServer):
    """test encrypted server"""

    api = aioesphomeapi.APIClient(
        "127.0.0.1",
        encrypted_server.port,
        None,
        noise_psk=encrypted_server.noise_psk,
    )

    logging.fatal("FIRST Connect - Start")
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

    await api.disconnect()


    logging.fatal("SECOND Connect - Start")
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

    await api.disconnect()

    logging.fatal("THIRD Connect - Start")
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

    await api.disconnect()

    assert False


async def test_encrypted_server_parallel(encrypted_server: EspHomeTestServer):
    """test encrypted server"""

    api1 = aioesphomeapi.APIClient(
        "127.0.0.1",
        encrypted_server.port,
        None,
        noise_psk=encrypted_server.noise_psk,
    )

    api2 = aioesphomeapi.APIClient(
        "127.0.0.1",
        encrypted_server.port,
        None,
        noise_psk=encrypted_server.noise_psk,
    )

    await api1.connect()
    await api2.connect()

    # Test API1 Hello
    assert api1.api_version.major == 1
    assert api1.api_version.minor == 42
    assert api1.log_name == "test_device @ 127.0.0.1"

    # Test API2 Hello
    assert api2.api_version.major == 1
    assert api2.api_version.minor == 42
    assert api2.log_name == "test_device @ 127.0.0.1"

    # Test Device Details
    device_info = await api1.device_info()
    device_info = await api2.device_info()

    assert device_info.name == "test_device"
    assert device_info.friendly_name == "friendly_test_device"
    assert device_info.bluetooth_mac_address == "B0:00:00:00:00:00"
    assert device_info.mac_address == "00:00:00:00:00:01"
    assert device_info.manufacturer == "Test Inc."
    assert device_info.model == "Test Model"
    assert device_info.suggested_area == "Test Area"

    await api1.disconnect()
    await api2.disconnect()

@pytest.mark.skip("Working but not sure if it tests what it should be")
async def test_encrypted_server_reconnect_logic(encrypted_server: EspHomeTestServer):
    """test encrypted server"""

    api = aioesphomeapi.APIClient(
        "127.0.0.1",
        encrypted_server.port,
        None,
        noise_psk=encrypted_server.noise_psk,
    )

    await api.connect()
    await api.disconnect()

    rl = ReconnectLogic(
        client=api,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=None,
        name="test_device",
    )
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED
    await rl.start()
    await sleep(0)
    await sleep(1)
    await api.disconnect()
    await sleep(10)