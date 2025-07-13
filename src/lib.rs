pub mod parser;
pub mod proto;
pub mod esphomeapi;

pub use parser::ProtoMessage;


pub fn to_packet(obj: ProtoMessage) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let response_content = parser::proto_to_vec(&obj)?;
    let message_type = parser::message_to_num(&obj)?;
    let zero: Vec<u8> = vec![0];
    let length: Vec<u8> = vec![response_content.len().try_into().unwrap()];
    let message_bit: Vec<u8> = vec![message_type];

    let answer_buf: Vec<u8> = [zero, length, message_bit, response_content].concat();
    Ok(answer_buf)
}

pub fn to_packet_from_ref(obj: &ProtoMessage) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let response_content = parser::proto_to_vec(&obj)?;
    let message_type = parser::message_to_num(&obj)?;
    let zero: Vec<u8> = vec![0];
    let length: Vec<u8> = vec![response_content.len().try_into().unwrap()];
    let message_bit: Vec<u8> = vec![message_type];

    let answer_buf: Vec<u8> = [zero, length, message_bit, response_content].concat();
    Ok(answer_buf)
}
