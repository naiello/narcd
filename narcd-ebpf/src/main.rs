#![no_std]
#![no_main]

use core::net::Ipv4Addr;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerfEventArray},
    programs::XdpContext,
};
use narcd_common::{Flow, FlowType, PacketDisposition, PacketSource};
use narcd_ebpf::util::ptr_at;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[map]
static PKTDISP: HashMap<PacketSource, PacketDisposition> = HashMap::with_max_entries(32, 0);

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
    let src_ip = unsafe { (*ipv4_hdr).src_addr() };
    let dst_ip = unsafe { (*ipv4_hdr).dst_addr() };
    match unsafe { (*ipv4_hdr).proto } {
        IpProto::Tcp => handle_tcp(ctx, src_ip, dst_ip),
        IpProto::Udp => handle_udp(ctx, src_ip, dst_ip),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

fn handle_tcp(ctx: XdpContext, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Result<u32, ()> {
    let tcp_hdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

    let src_port = u16::from_be_bytes(unsafe { (*tcp_hdr).source });
    let dst_port = u16::from_be_bytes(unsafe { (*tcp_hdr).dest });
    let is_syn = unsafe { (*tcp_hdr).syn() } > 0;
    let is_ack = unsafe { (*tcp_hdr).ack() } > 0;

    if !is_syn || is_ack {
        return Ok(xdp_action::XDP_PASS);
    }

    let disposition = get_packet_disposition(dst_port, IpProto::Tcp);
    if !matches!(disposition, PacketDisposition::Ignore) {
        let flow = Flow {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            flow_type: FlowType::Syn,
        };
        EVENTS.output(&ctx, flow, 0);
    }

    match disposition {
        PacketDisposition::Drop => Ok(xdp_action::XDP_DROP),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

fn handle_udp(ctx: XdpContext, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Result<u32, ()> {
    let udp_hdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

    let src_port = u16::from_be_bytes(unsafe { (*udp_hdr).src });
    let dst_port = u16::from_be_bytes(unsafe { (*udp_hdr).dst });

    let disposition = get_packet_disposition(dst_port, IpProto::Udp);
    if !matches!(disposition, PacketDisposition::Ignore) {
        let flow = Flow {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            flow_type: FlowType::Udp,
        };
        EVENTS.output(&ctx, flow, 0);
    }

    match disposition {
        PacketDisposition::Drop => Ok(xdp_action::XDP_DROP),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

fn get_packet_disposition(dst_port: u16, proto: IpProto) -> PacketDisposition {
    let key = PacketSource {
        dst_port,
        proto: proto as u8,
    };

    unsafe { PKTDISP.get(&key) }
        .copied()
        .unwrap_or(PacketDisposition::Pass)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
