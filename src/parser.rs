use crate::proto::version_2025_6_3::{
    AlarmControlPanelCommandRequest, AlarmControlPanelStateResponse, BinarySensorStateResponse,
    BluetoothConnectionsFreeResponse, BluetoothDeviceClearCacheResponse,
    BluetoothDeviceConnectionResponse, BluetoothDevicePairingResponse, BluetoothDeviceRequest,
    BluetoothDeviceUnpairingResponse, BluetoothGattErrorResponse,
    BluetoothGattGetServicesDoneResponse, BluetoothGattGetServicesRequest,
    BluetoothGattGetServicesResponse, BluetoothGattNotifyDataResponse, BluetoothGattNotifyRequest,
    BluetoothGattNotifyResponse, BluetoothGattReadDescriptorRequest, BluetoothGattReadRequest,
    BluetoothGattReadResponse, BluetoothGattWriteDescriptorRequest, BluetoothGattWriteRequest,
    BluetoothGattWriteResponse, BluetoothLeAdvertisementResponse,
    BluetoothLeRawAdvertisementsResponse, ButtonCommandRequest, CameraImageRequest,
    CameraImageResponse, ClimateCommandRequest, ClimateStateResponse, ConnectRequest,
    ConnectResponse, CoverCommandRequest, CoverStateResponse, DateCommandRequest,
    DateStateResponse, DateTimeCommandRequest, DateTimeStateResponse, DeviceInfoRequest,
    DeviceInfoResponse, DisconnectRequest, DisconnectResponse, EventResponse,
    ExecuteServiceRequest, FanCommandRequest, FanStateResponse, GetTimeRequest, GetTimeResponse,
    HelloRequest, HelloResponse, HomeAssistantStateResponse, HomeassistantServiceResponse,
    LightCommandRequest, LightStateResponse, ListEntitiesAlarmControlPanelResponse,
    ListEntitiesBinarySensorResponse, ListEntitiesButtonResponse, ListEntitiesCameraResponse,
    ListEntitiesClimateResponse, ListEntitiesCoverResponse, ListEntitiesDateResponse,
    ListEntitiesDateTimeResponse, ListEntitiesDoneResponse, ListEntitiesEventResponse,
    ListEntitiesFanResponse, ListEntitiesLightResponse, ListEntitiesLockResponse,
    ListEntitiesMediaPlayerResponse, ListEntitiesNumberResponse, ListEntitiesRequest,
    ListEntitiesSelectResponse, ListEntitiesSensorResponse, ListEntitiesServicesResponse,
    ListEntitiesSwitchResponse, ListEntitiesTextResponse, ListEntitiesTextSensorResponse,
    ListEntitiesTimeResponse, ListEntitiesUpdateResponse, ListEntitiesValveResponse,
    LockCommandRequest, LockStateResponse, MediaPlayerCommandRequest, MediaPlayerStateResponse,
    NumberCommandRequest, NumberStateResponse, PingRequest, PingResponse, SelectCommandRequest,
    SelectStateResponse, SensorStateResponse, SubscribeBluetoothConnectionsFreeRequest,
    SubscribeBluetoothLeAdvertisementsRequest, SubscribeHomeAssistantStateResponse,
    SubscribeHomeAssistantStatesRequest, SubscribeHomeassistantServicesRequest,
    SubscribeLogsRequest, SubscribeLogsResponse, SubscribeStatesRequest,
    SubscribeVoiceAssistantRequest, SwitchCommandRequest, SwitchStateResponse, TextCommandRequest,
    TextSensorStateResponse, TextStateResponse, TimeCommandRequest, TimeStateResponse,
    UnsubscribeBluetoothLeAdvertisementsRequest, UpdateCommandRequest, UpdateStateResponse,
    ValveCommandRequest, ValveStateResponse, VoiceAssistantAnnounceFinished,
    VoiceAssistantAnnounceRequest, VoiceAssistantAudio, VoiceAssistantConfigurationRequest,
    VoiceAssistantConfigurationResponse, VoiceAssistantEventResponse, VoiceAssistantRequest,
    VoiceAssistantResponse, VoiceAssistantSetConfiguration, VoiceAssistantTimerEventResponse,
};
use prost::Message;

macro_rules! proto_message_mappings {
    ($($type_id:expr => $struct:ident),* $(,)?) => {
        // Generate the ProtoMessage enum
        #[derive(Clone, Debug)]
        pub enum ProtoMessage {
            $(
                $struct($struct),
            )*
        }

        // Generate the parse_proto_message function
        pub fn parse_proto_message(message_type: usize, buf: &[u8]) -> Result<ProtoMessage, &'static str> {
            match message_type {
                $(
                    $type_id => $struct::decode(buf)
                        .map(ProtoMessage::$struct)
                        .map_err(|_| concat!("Failed to decode ", stringify!($struct))),
                )*
                _ => Err(Box::leak(format!("Unknown message type: {}", message_type).into_boxed_str())),
            }
        }

        pub fn proto_to_vec(message: &ProtoMessage) -> Result<Vec<u8>, &'static str> {
            match message {
                $(
                    ProtoMessage::$struct(msg) => {
                        
                        Ok(msg.encode_to_vec())
                    }
                )*
            }
        }

        // Generate the parse_proto_message function
        pub fn message_to_num(message_type: &ProtoMessage) -> Result<u8, &'static str> {
            match message_type {
                $(
                    ProtoMessage::$struct(_) => Ok($type_id),
                )*
            }
        }
    };
}

// Message types as in
// https://github.com/esphome/aioesphomeapi/blob/main/aioesphomeapi/core.py#L290
proto_message_mappings!(
    1 => HelloRequest,
    2 => HelloResponse,
    3 => ConnectRequest,
    4 => ConnectResponse,
    5 => DisconnectRequest,
    6 => DisconnectResponse,
    7 => PingRequest,
    8 => PingResponse,
    9 => DeviceInfoRequest,
    10 => DeviceInfoResponse,
    11 => ListEntitiesRequest,
    12 => ListEntitiesBinarySensorResponse,
    13 => ListEntitiesCoverResponse,
    14 => ListEntitiesFanResponse,
    15 => ListEntitiesLightResponse,
    16 => ListEntitiesSensorResponse,
    17 => ListEntitiesSwitchResponse,
    18 => ListEntitiesTextSensorResponse,
    19 => ListEntitiesDoneResponse,
    20 => SubscribeStatesRequest,
    21 => BinarySensorStateResponse,
    22 => CoverStateResponse,
    23 => FanStateResponse,
    24 => LightStateResponse,
    25 => SensorStateResponse,
    26 => SwitchStateResponse,
    27 => TextSensorStateResponse,
    28 => SubscribeLogsRequest,
    29 => SubscribeLogsResponse,
    30 => CoverCommandRequest,
    31 => FanCommandRequest,
    32 => LightCommandRequest,
    33 => SwitchCommandRequest,
    34 => SubscribeHomeassistantServicesRequest,
    35 => HomeassistantServiceResponse,
    36 => GetTimeRequest,
    37 => GetTimeResponse,
    38 => SubscribeHomeAssistantStatesRequest,
    39 => SubscribeHomeAssistantStateResponse,
    40 => HomeAssistantStateResponse,
    41 => ListEntitiesServicesResponse,
    42 => ExecuteServiceRequest,
    43 => ListEntitiesCameraResponse,
    44 => CameraImageResponse,
    45 => CameraImageRequest,
    46 => ListEntitiesClimateResponse,
    47 => ClimateStateResponse,
    48 => ClimateCommandRequest,
    49 => ListEntitiesNumberResponse,
    50 => NumberStateResponse,
    51 => NumberCommandRequest,
    52 => ListEntitiesSelectResponse,
    53 => SelectStateResponse,
    54 => SelectCommandRequest,
    // 55 => ListEntitiesSirenResponse,
    // 56 => SirenStateResponse,
    // 57 => SirenCommandRequest,
    58 => ListEntitiesLockResponse,
    59 => LockStateResponse,
    60 => LockCommandRequest,
    61 => ListEntitiesButtonResponse,
    62 => ButtonCommandRequest,
    63 => ListEntitiesMediaPlayerResponse,
    64 => MediaPlayerStateResponse,
    65 => MediaPlayerCommandRequest,
    66 => SubscribeBluetoothLeAdvertisementsRequest,
    67 => BluetoothLeAdvertisementResponse,
    68 => BluetoothDeviceRequest,
    69 => BluetoothDeviceConnectionResponse,
    70 => BluetoothGattGetServicesRequest,
    71 => BluetoothGattGetServicesResponse,
    72 => BluetoothGattGetServicesDoneResponse,
    73 => BluetoothGattReadRequest,
    74 => BluetoothGattReadResponse,
    75 => BluetoothGattWriteRequest,
    76 => BluetoothGattReadDescriptorRequest,
    77 => BluetoothGattWriteDescriptorRequest,
    78 => BluetoothGattNotifyRequest,
    79 => BluetoothGattNotifyDataResponse,
    80 => SubscribeBluetoothConnectionsFreeRequest,
    81 => BluetoothConnectionsFreeResponse,
    82 => BluetoothGattErrorResponse,
    83 => BluetoothGattWriteResponse,
    84 => BluetoothGattNotifyResponse,
    85 => BluetoothDevicePairingResponse,
    86 => BluetoothDeviceUnpairingResponse,
    87 => UnsubscribeBluetoothLeAdvertisementsRequest,
    88 => BluetoothDeviceClearCacheResponse,
    89 => SubscribeVoiceAssistantRequest,
    90 => VoiceAssistantRequest,
    91 => VoiceAssistantResponse,
    92 => VoiceAssistantEventResponse,
    93 => BluetoothLeRawAdvertisementsResponse,
    94 => ListEntitiesAlarmControlPanelResponse,
    95 => AlarmControlPanelStateResponse,
    96 => AlarmControlPanelCommandRequest,
    97 => ListEntitiesTextResponse,
    98 => TextStateResponse,
    99 => TextCommandRequest,
    100 => ListEntitiesDateResponse,
    101 => DateStateResponse,
    102 => DateCommandRequest,
    103 => ListEntitiesTimeResponse,
    104 => TimeStateResponse,
    105 => TimeCommandRequest,
    106 => VoiceAssistantAudio,
    107 => ListEntitiesEventResponse,
    108 => EventResponse,
    109 => ListEntitiesValveResponse,
    110 => ValveStateResponse,
    111 => ValveCommandRequest,
    112 => ListEntitiesDateTimeResponse,
    113 => DateTimeStateResponse,
    114 => DateTimeCommandRequest,
    115 => VoiceAssistantTimerEventResponse,
    116 => ListEntitiesUpdateResponse,
    117 => UpdateStateResponse,
    118 => UpdateCommandRequest,
    119 => VoiceAssistantAnnounceRequest,
    120 => VoiceAssistantAnnounceFinished,
    121 => VoiceAssistantConfigurationRequest,
    122 => VoiceAssistantConfigurationResponse,
    123 => VoiceAssistantSetConfiguration,
);
