#![no_std]
#![no_main]

use aya_ebpf::{
    Global,
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    helpers::generated::bpf_ktime_get_ns,
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};
use core::mem;

type TcAct = i32;
type Ipv4Addr = u32;

// because we attach ebpf to wireguard interface we only deal with l3 packets so the offsets are from ip header
const IPV4_SRC_OFFSET: usize = 12;
const IPV4_DST_OFFSET: usize = 16;

#[unsafe(no_mangle)]
static BURST_BYTES: Global<u64> = Global::new(0);

#[unsafe(no_mangle)]
static INGRESS_BYTES_PER_SEC: Global<u64> = Global::new(0);

#[unsafe(no_mangle)]
static EGRESS_BYTES_PER_SEC: Global<u64> = Global::new(0);

#[map]
static EGRESS_STATE: HashMap<Ipv4Addr, State> = HashMap::with_max_entries(4096, 0);

#[map]
static INGRESS_STATE: HashMap<Ipv4Addr, State> = HashMap::with_max_entries(4096, 0);

#[repr(C)]
#[derive(Default)]
struct State {
    // could be u32 but we will be aligned to u64 because of time so lets keep this u64, also saves us some casts
    tokens: u64,
    last_ns: u64,
}

#[classifier]
pub fn wgtc_ingress(ctx: TcContext) -> TcAct {
    police_packet(
        &ctx,
        IPV4_DST_OFFSET,
        INGRESS_BYTES_PER_SEC.load(),
        &INGRESS_STATE,
    )
}

#[classifier]
pub fn wgtc_egress(ctx: TcContext) -> TcAct {
    police_packet(
        &ctx,
        IPV4_SRC_OFFSET,
        EGRESS_BYTES_PER_SEC.load(),
        &EGRESS_STATE,
    )
}

// probably will be inlined by compiler but lets be sure
#[inline(always)]
fn police_packet(
    ctx: &TcContext,
    ip_offset: usize,
    rate: u64,
    state: &HashMap<Ipv4Addr, State>,
) -> TcAct {
    let ip = unsafe { ptr_at::<u32>(&ctx, ip_offset) };
    let Ok(ip) = ip.map(|ip| unsafe { *ip }) else {
        return TC_ACT_SHOT;
    };
    let state = match state.get_ptr_mut(ip) {
        None => {
            let new_state = State::default();
            if state.insert(ip, new_state, 0).is_err() {
                return TC_ACT_SHOT;
            };
            state
                .get_ptr_mut(ip)
                // unreachable, only here to satisfy validator
                .unwrap_or_else(|| &mut State::default())
        }
        Some(state) => state,
    };
    let state = unsafe { &mut *state };
    let now = unsafe { bpf_ktime_get_ns() };

    let refill = (now - state.last_ns) * rate / 1_000_000_000;
    state.tokens += refill;
    if refill > BURST_BYTES.load() {
        state.tokens = BURST_BYTES.load();
    }

    state.last_ns = now;
    if state.tokens >= ctx.len() as u64 {
        state.tokens -= ctx.len() as u64;
        TC_ACT_OK
    } else {
        TC_ACT_SHOT
    }
}

// used for debugging
#[allow(dead_code)]
#[cfg(feature = "log")]
fn print_packet(ctx: &TcContext) -> Result<(), ()> {
    use aya_log_ebpf::info;
    use network_types::{
        ip::{IpProto, Ipv4Hdr},
        udp::UdpHdr,
    };

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, 0)? };
    let protocol = unsafe { (*ipv4hdr).proto };
    let src = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });
    let dst = u32::from_be_bytes(unsafe { (*ipv4hdr).dst_addr });

    if protocol == IpProto::Udp || protocol == IpProto::Tcp {
        let proto_name = if protocol == IpProto::Udp {
            "udp"
        } else {
            "tcp"
        };
        let udp: *const UdpHdr = unsafe { ptr_at(ctx, Ipv4Hdr::LEN)? };
        let src_port = unsafe { (*udp).src_port() };
        let dst_port = unsafe { (*udp).dst_port() };
        info!(
            ctx,
            "{:i}:{} --{}--> {:i}:{}", src, src_port, proto_name, dst, dst_port
        );
    } else {
        info!(ctx, "{:i} --({})--> {:i}", src, protocol as u8, dst);
    }
    Ok(())
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let (start, end) = (ctx.data(), ctx.data_end());
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    let ptr = (start + offset) as *const T;
    Ok(unsafe { &*ptr })
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
