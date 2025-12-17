#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::PerfEventArray,
    programs::XdpContext,
};
use narcd_common::{Flow, FlowType};
use narcd_ebpf::util::ptr_at;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

#[map]
static EVENTS: PerfEventArray<Flow> = PerfEventArray::new(0);

#[xdp]
pub fn narcd(ctx: XdpContext) -> u32 {
    match process_packet(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn process_packet(ctx: XdpContext) -> Result<u32, ()> {
    let eth_hdr: *const EthHdr = ptr_at(&ctx, 0)?;

    let eth_type = unsafe { (*eth_hdr).ether_type() };
    if !matches!(eth_type, Ok(EtherType::Ipv4)) {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4_hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let proto = unsafe { (*ipv4_hdr).proto };
    if !matches!(proto, IpProto::Tcp) {
        return Ok(xdp_action::XDP_PASS);
    }
    let tcp_hdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

    let src_ip = unsafe { (*ipv4_hdr).src_addr() };
    let dst_ip = unsafe { (*ipv4_hdr).dst_addr() };
    let src_port = u16::from_be_bytes(unsafe { (*tcp_hdr).source });
    let dst_port = u16::from_be_bytes(unsafe { (*tcp_hdr).dest });
    let is_syn = unsafe { (*tcp_hdr).syn() } > 0;
    let is_ack = unsafe { (*tcp_hdr).ack() } > 0;

    if !is_syn || is_ack {
        return Ok(xdp_action::XDP_PASS);
    }

    let flow = Flow {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        flow_type: FlowType::Syn,
    };
    EVENTS.output(&ctx, flow, 0);

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
