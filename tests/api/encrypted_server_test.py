
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

    # List all entities of the device (order should be alphabetical)
    entities, services = await api.list_entities_services()
    print("entities", entities, services)

    assert len(entities) == 5, entities
    binary_sensor = next((e for e in entities if isinstance(e, aioesphomeapi.BinarySensorInfo)))
    light = next((e for e in entities if isinstance(e, aioesphomeapi.LightInfo)))
    button = next((e for e in entities if isinstance(e, aioesphomeapi.ButtonInfo)))
    switch = next((e for e in entities if isinstance(e, aioesphomeapi.SwitchInfo)))
    sensor = next((e for e in entities if isinstance(e, aioesphomeapi.SensorInfo)))

    assert isinstance(binary_sensor, aioesphomeapi.BinarySensorInfo)
    assert binary_sensor.unique_id == "test_binary_sensor_unique_id"
    assert binary_sensor.name == "test_binary_sensor"
    assert binary_sensor.key == 3
    assert binary_sensor.icon == "mdi:test-binary-sensor-icon"
    assert binary_sensor.device_class == "test_binary_sensor_device_class"
    assert binary_sensor.disabled_by_default is False
    assert binary_sensor.entity_category == aioesphomeapi.EntityCategory.NONE
    assert binary_sensor.object_id == "test_binary_sensor_object_id"

    assert isinstance(button, aioesphomeapi.ButtonInfo)
    assert button.unique_id == "test_button_unique_id"
    assert button.name == "test_button"
    assert button.key == 0
    assert button.icon == "mdi:test-button-icon"
    assert button.device_class == "test_button_device_class"
    assert button.disabled_by_default is False
    assert button.entity_category == aioesphomeapi.EntityCategory.NONE
    assert button.object_id == "test_button_object_id"

    assert isinstance(switch, aioesphomeapi.SwitchInfo)
    assert switch.unique_id == "test_switch_unique_id"
    assert switch.name == "test_switch"
    assert switch.key == 1
    assert switch.icon == "mdi:test-switch-icon"
    assert switch.device_class == "test_switch_device_class"
    assert switch.disabled_by_default is False
    assert switch.entity_category == aioesphomeapi.EntityCategory.NONE
    assert switch.object_id == "test_switch_object_id"

    assert isinstance(light, aioesphomeapi.LightInfo)
    assert light.unique_id == "test_light_unique_id"
    assert light.name == "test_light"
    assert light.key == 4
    assert light.icon == "mdi:test-light-icon"
    assert light.disabled_by_default is False
    assert light.entity_category == aioesphomeapi.EntityCategory.NONE
    assert light.object_id == "test_light_object_id"

    assert isinstance(sensor, aioesphomeapi.SensorInfo)
    assert sensor.unique_id == "test_sensor_unique_id"
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

    api.disconnect()
