use anyhow::Context;
use aya::{
    Ebpf,
    maps::{HashMap as EbpfHashMap, MapData},
};
use std::{collections::HashSet, net::Ipv4Addr, time::Duration};

type EbpfIpv4Addr = u32;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct State {
    tokens: u64,
    last_ns: u64,
}

unsafe impl aya::Pod for State {}

const CLEANUP_INTERVAL: Duration = Duration::from_secs(5);

const MAXIMUM_IDLE_TIME_NS: u64 = 5 * 60 * 1_000_000_000;

pub fn cleanup_states_indefinitly(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let mut egress_state: EbpfHashMap<_, EbpfIpv4Addr, State> = EbpfHashMap::try_from(
        ebpf.take_map("EGRESS_STATE")
            .with_context(|| "couldn't find map")?,
    )
    .with_context(|| "couldn't cast ebpf map to hashmap")?;

    let mut ingress_state: EbpfHashMap<_, EbpfIpv4Addr, State> = EbpfHashMap::try_from(
        ebpf.take_map("INGRESS_STATE")
            .with_context(|| "couldn't find map")?,
    )
    .with_context(|| "couldn't cast ebpf map to hashmap")?;

    loop {
        std::thread::sleep(CLEANUP_INTERVAL);
        let mut peers_left = HashSet::new();
        let now_time = nanos_since_boot()?;
        remove_inactive_peers(now_time, &mut egress_state, &mut peers_left);
        remove_inactive_peers(now_time, &mut ingress_state, &mut peers_left);
        log::info!("{} active peers", peers_left.len());
    }
}

fn remove_inactive_peers(
    now_time: u64,
    ip_to_state: &mut EbpfHashMap<MapData, EbpfIpv4Addr, State>,
    peers_left: &mut HashSet<u32>,
) {
    let mut peers_to_remove = HashSet::new();
    let mut iter = ip_to_state.iter();
    while let Some(Ok((ip, state))) = iter.next() {
        if now_time.saturating_sub(state.last_ns) > MAXIMUM_IDLE_TIME_NS {
            peers_to_remove.insert(ip);
        }
        peers_left.insert(ip);
    }
    for ip in peers_to_remove {
        if let Err(err) = ip_to_state.remove(&ip) {
            log::warn!(
                "couldn't remove inactive peer '{}': {err:?}",
                Ipv4Addr::from_bits(ip.to_be())
            )
        }
    }
}

// userspace equivalent of bpf_ktime_get_ns
fn nanos_since_boot() -> anyhow::Result<u64> {
    let spec = nix::time::ClockId::CLOCK_MONOTONIC
        .now()
        .with_context(|| "couldn't get current time since boot")?;
    Ok(spec.tv_nsec() as u64)
}
