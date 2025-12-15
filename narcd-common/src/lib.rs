#![no_std]

pub struct Flow {
    pub src_ip: u32,
    pub src_port: u16,
    pub dst_ip: u32,
    pub dst_port: u16,
    pub flow_type: FlowType,
}

pub enum FlowType {
    Syn,
}
