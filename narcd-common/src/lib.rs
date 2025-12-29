#![cfg_attr(not(feature = "std"), no_std)]

use core::net::Ipv4Addr;

#[cfg_attr(feature = "std", derive(PartialEq, Eq, Debug))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Flow {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    pub flow_type: FlowType,
}

#[cfg_attr(feature = "std", derive(PartialEq, Eq, Debug, Hash, Clone, Copy))]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
pub enum FlowType {
    Syn,
    Udp,
}

#[cfg_attr(feature = "std", derive(PartialEq, Eq, Debug, Hash, Clone, Copy))]
pub struct PacketSource {
    pub dst_port: u16,
    pub proto: u8,
}

#[cfg(feature = "std")]
unsafe impl aya::Pod for PacketSource {}

#[cfg_attr(feature = "std", derive(PartialEq, Eq, Debug, Hash))]
#[derive(Clone, Copy)]
pub enum PacketDisposition {
    Pass,
    Ignore,
    Drop,
}

#[cfg(feature = "std")]
unsafe impl aya::Pod for PacketDisposition {}
