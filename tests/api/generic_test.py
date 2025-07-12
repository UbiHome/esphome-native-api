
from asyncio import sleep
import os
from pprint import pp
from unittest import IsolatedAsyncioTestCase
import aioesphomeapi

from tests.conftest import TestServer


async def test_run(test_server: TestServer):
    """test simple server"""

    api = aioesphomeapi.APIClient("127.0.0.1", test_server.port, "")
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

    # List all entities of the device
    entities = await api.list_entities_services()
    pp(entities)

        # await api.disconnect()

        # entities, services = await api.list_entities_services()
        # print("switches", entities, services)
        # assert len(entities) == 1, entities
        # entity = entities[0]

        # assert type(entity) == aioesphomeapi.SwitchInfo
        # assert entity.unique_id == button_id
        # assert entity.name == button_name

        # mock = Mock()
        # # Subscribe to the state changes
        # api.subscribe_states(mock)
        
        # # Test switching the switch on via command
        # api.switch_command(0, True)
        # assert wait_and_get_file(switch_mock) == "true\n"

        # # State update should be send back
        # while not mock.called:
        #   await sleep(0.1)
        # state = mock.call_args.args[0]
        # assert state.state == True
        # os.remove(switch_mock)
        # mock.reset_mock()

        # # Test switching the switch off via command
        # api.switch_command(0, False)
        # assert wait_and_get_file(switch_mock) == "false\n"
        # # State update should be send back
        # while not mock.called:
        #   await sleep(0.1)
        # state = mock.call_args.args[0]
        # assert state.state == False
        # mock.reset_mock()
        # os.remove(switch_mock)

        # # Test switching the switch on via local change
        # with open(switch_mock, "w") as f:
        #   f.write("true")

        # # Wait for the state change
        # while not mock.called:
        #   await sleep(0.1)
        # state = mock.call_args.args[0]
        # assert state.state == True

