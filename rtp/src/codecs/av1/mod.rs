use crate::{
    error::{Error, Result},
    packetizer::{Depacketizer, Payloader},
};
use bytes::{BufMut, Bytes, BytesMut};

const Z_MASK: u8 = 0b10000000;
const Z_BITSHIFT: usize = 7;

const Y_MASK: u8 = 0b01000000;
const Y_BITSHIFT: usize = 6;

const W_MASK: u8 = 0b00110000;
const W_BITSHIFT: usize = 4;

const N_MASK: u8 = 0b00001000;
const N_BITSHIFT: usize = 3;

const AV1_PAYLOADER_HEADER_SIZE: usize = 1;

#[derive(Default, Debug, Clone)]
pub struct AV1Payloader {}

#[derive(Debug)]
pub enum ObuType {
    SequenceHeader = 1,
    TemporalDelimiter = 2,
    FrameHeader = 3,
    TileGroup = 4,
    Metadata = 5,
    Frame = 6,
    RedundantFrameHeader = 7,
    TileList = 8,
    Padding = 15,
}

pub struct ObuHeader {
    pub obu_type: ObuType,
    pub has_size: bool,
    pub extension: Option<ObuExtension>,
}

#[derive(Debug)]
pub struct ObuExtension {
    pub temporal_id: u8,
    pub spatial_id: u8,
}

impl ObuType {
    pub fn parse(byte: u8) -> ObuType {
        match (byte & 0b01111_000) >> 3 {
            1 => ObuType::SequenceHeader,
            2 => ObuType::TemporalDelimiter,
            3 => ObuType::FrameHeader,
            4 => ObuType::TileGroup,
            5 => ObuType::Metadata,
            6 => ObuType::Frame,
            7 => ObuType::RedundantFrameHeader,
            8 => ObuType::TileList,
            15 => ObuType::Padding,
            _ => panic!("Invalid OBU type"),
        }
    }
}

impl ObuHeader {
    pub fn parse(byte1: u8, byte2: Option<u8>) -> ObuHeader {
        let obu_type = ObuType::parse(byte1);
        let has_extension = (byte1 & 0b0000_0100) != 0;
        let has_size = (byte1 & 0b0000_0010) != 0;
        let forbidden_bit = byte1 & 0b1000_0000;
        assert_eq!(forbidden_bit, 0);

        let extension = if has_extension {
            let byte2 = byte2.expect("Extension bit set");
            let temporal_id = (byte2 & 0b1110_0000) >> 5;
            let spatial_id = (byte2 & 0b0001_1000) >> 3;
            Some(ObuExtension {
                temporal_id,
                spatial_id,
            })
        } else {
            None
        };

        ObuHeader {
            obu_type,
            has_size,
            extension,
        }
    }

    pub fn len(&self) -> usize {
        if self.extension.is_some() {
            2
        } else {
            1
        }
    }
}

impl Payloader for AV1Payloader {
    fn payload(&mut self, mtu: usize, payload: &Bytes) -> Result<Vec<Bytes>> {
        let mut payloads = vec![];
        let mut remaining = payload.slice(0..);

        while !remaining.is_empty() {
            let header = ObuHeader::parse(remaining[0], remaining.get(1).copied());
            let header_len = header.len();
            let (obu_len, len_len) = if header.has_size {
                decode_leb128(&remaining[header_len..])?
            } else {
                (0u64, 0)
            };
            // println!("EXTENSION HEADER {:?}", header.extension);
            let obu_len = obu_len as usize;
            match header.obu_type {
                ObuType::TemporalDelimiter => {
                    // Skip
                }
                ObuType::TileList => { /* don't send these */ }
                ty => {
                    let set_n_bit = if let ObuType::SequenceHeader = ty {
                        true
                    } else {
                        false
                    };
                    // println!("OBU type: {:?}", ty);
                    let obu = remaining.slice(0..header_len + len_len + obu_len);
                    payloads.extend(self.do_payload(mtu, &obu, set_n_bit).unwrap().into_iter());
                }
            }
            remaining = remaining.slice(header_len + len_len + obu_len..);
        }
        Ok(payloads)
    }
    fn clone_to(&self) -> Box<dyn Payloader + Send + Sync> {
        Box::new(self.clone())
    }
}

impl AV1Payloader {
    fn do_payload(&mut self, mtu: usize, payload: &Bytes, set_n_bit: bool) -> Result<Vec<Bytes>> {
        let max_fragment_size = (mtu as isize - AV1_PAYLOADER_HEADER_SIZE as isize - 2) as usize;
        let mut payload_data_remaining = payload.len();
        let mut payload_data_index = 0;
        let mut payloads = vec![];
        if max_fragment_size.min(payload_data_remaining) <= 0 {
            return Ok(payloads);
        }

        // println!(
        //     "JUAN payloading... first 2 bytes: {:02X} {:02X}",
        //     payload[0], payload[1]
        // );
        while payload_data_remaining > 0 {
            let current_fragment_size = std::cmp::min(max_fragment_size, payload_data_remaining);
            let leb128_size = if current_fragment_size > 127 { 2 } else { 1 };
            let mut out = BytesMut::with_capacity(
                AV1_PAYLOADER_HEADER_SIZE + leb128_size + current_fragment_size,
            );
            out.put_u8(0);

            let leb128_value = encode_leb128_2(current_fragment_size as u64);
            if leb128_size == 1 {
                out.put_u8(leb128_value as u8);
            } else {
                out.put_u8(leb128_value as u8);
                out.put_u8((leb128_value >> 8) as u8);
            }

            out.put(&payload[payload_data_index..payload_data_index + current_fragment_size]);

            // out[AV1_PAYLOADER_HEADER_SIZE + leb128_size..].copy_from_slice(
            //     &payload[payload_data_index..payload_data_index + current_fragment_size],
            // );

            if !payloads.is_empty() {
                out[0] ^= Z_MASK;
            }
            if payload_data_remaining > current_fragment_size {
                out[0] ^= Y_MASK;
            }
            if set_n_bit {
                out[0] ^= N_MASK;
            }
            // println!(
            //     " JUAN HEADER = {}. Z and Y bits: {} {}. len={} => {} (leb)",
            //     out[0],
            //     out[0] & Z_MASK != 0,
            //     out[0] & Y_MASK != 0,
            //     current_fragment_size,
            //     leb128_value
            // );

            payloads.push(out.freeze());
            payload_data_remaining -= current_fragment_size;
            payload_data_index += current_fragment_size;
        }
        // println!("  JUAN payloads: {}", payloads.len());

        Ok(payloads)
    }
}

fn encode_leb128(value: u64) -> u64 {
    let mut value = value;
    let mut out = 0;
    let mut shift = 0;

    loop {
        out |= (value & 0x7F) << shift;
        value = value >> 7;
        if value == 0 {
            break;
        }
        out |= 0x80 << shift;
        shift += 8;
    }

    out
}

fn encode_leb128_2(mut value: u64) -> u64 {
    let mut encoded_value: u64 = 0;
    let mut shift: u32 = 0;

    loop {
        let mut byte: u8 = (value & 0x7F) as u8;
        value >>= 7;

        if value != 0 {
            byte |= 0x80; // Set the continuation bit
        }

        encoded_value |= (byte as u64) << shift;
        shift += 8;

        if value == 0 {
            break;
        }
    }

    encoded_value
}

fn decode_leb128(data: &[u8]) -> Result<(u64, usize)> {
    let mut value = 0;
    let mut shift = 0;
    let mut bytes_read = 0;

    for byte in data {
        value |= ((byte & 0x7F) as u64) << shift;
        shift += 7;
        bytes_read += 1;
        if byte & 0x80 == 0 {
            break;
        }
    }

    if shift >= 64 && data[bytes_read - 1] & 0x80 != 0 {
        return Err(Error::Other("Overflow while decoding LEB128".to_owned()));
    }

    Ok((value, bytes_read))
}
