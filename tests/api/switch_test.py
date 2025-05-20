
from asyncio import sleep
import os
from unittest.mock import Mock
import aioesphomeapi
from utils import TestServer


async def test_run():
  button_id = "my_switch"
  button_name = "Switch it"
  switch_mock = "test_switch.mock"

  async with TestServer() as ubihome:
    api = aioesphomeapi.APIClient("127.0.0.1", 6053, "MyPassword")
    await api.connect(login=True)

    entities, services = await api.list_entities_services()
    print("switches", entities, services)
    assert len(entities) == 1, entities
    entity = entities[0]

    assert type(entity) == aioesphomeapi.SwitchInfo
    assert entity.unique_id == button_id
    assert entity.name == button_name

    mock = Mock()
    # Subscribe to the state changes
    api.subscribe_states(mock)
    
    # Test switching the switch on via command
    api.switch_command(0, True)
    assert wait_and_get_file(switch_mock) == "true\n"

    # State update should be send back
    while not mock.called:
      await sleep(0.1)
    state = mock.call_args.args[0]
    assert state.state == True
    os.remove(switch_mock)
    mock.reset_mock()

    # Test switching the switch off via command
    api.switch_command(0, False)
    assert wait_and_get_file(switch_mock) == "false\n"
    # State update should be send back
    while not mock.called:
      await sleep(0.1)
    state = mock.call_args.args[0]
    assert state.state == False
    mock.reset_mock()
    os.remove(switch_mock)

    # Test switching the switch on via local change
    with open(switch_mock, "w") as f:
      f.write("true")

    # Wait for the state change
    while not mock.called:
      await sleep(0.1)
    state = mock.call_args.args[0]
    assert state.state == True

