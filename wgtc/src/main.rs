use anyhow::{Context, ensure};
use aya::{
    Ebpf,
    programs::{
        SchedClassifier, TcAttachType,
        tc::{self, SchedClassifierLinkId},
    },
    util::KernelVersion,
};
use clap::Parser;
use log::LevelFilter;
use simple_logger::SimpleLogger;

mod cleanup;

#[derive(clap::Parser, Debug)]
struct Args {
    /// Interface to attach ebpf to
    #[arg(short, long)]
    interface: String,

    /// Ingress bandwidth limit, Mbit/Sec
    #[arg(long)]
    ingress: Option<u32>,

    /// Egress bandwidth limit, Mbit/Sec
    #[arg(long)]
    egress: Option<u32>,

    /// Burst in KByte
    #[arg(short, long, default_value = "128")]
    burst: u32,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    ensure!(
        args.egress.is_some() || args.ingress.is_some(),
        "either --ingress or --egress must be provided"
    );

    SimpleLogger::default()
        .with_level(LevelFilter::Info)
        .with_module_level("aya", LevelFilter::Error)
        .init()
        .with_context(|| "couldn't setup logger")?;

    if !is_using_tcx() {
        cleanup_netlink_qdiscs(&args.interface);
        let if_name = args.interface.clone();
        if let Err(err) = ctrlc::set_handler(move || {
            cleanup_netlink_qdiscs(&if_name);
            log::info!("removing netlink qdiscs");
            std::process::exit(0);
        }) {
            log::warn!("couldn't setup ctrl c handler to cleanup qdisc: {err:?}");
        }
    }

    let ingress_rate = args.ingress.unwrap_or(0) as u64 * 1024 * 1024 / 8;
    let egress_rate = args.egress.unwrap_or(0) as u64 * 1024 * 1024 / 8;

    let mut ebpf = aya::EbpfLoader::new()
        .override_global("BURST_BYTES", &(args.burst as u64 * 1024), true)
        .override_global("INGRESS_BYTES_PER_SEC", &ingress_rate, true)
        .override_global("EGRESS_BYTES_PER_SEC", &egress_rate, true)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/wgtc_ebpf"
        )))?;

    #[cfg(feature = "ebpf_log")]
    if let Err(error) = setup_ebpf_logger(&mut ebpf) {
        log::warn!("couldn't setup ebpf logger: {error:?}");
    }

    let mut programs = Vec::new();
    if let Some(bandwidth) = args.ingress {
        // because of wg server behaviour, the egress and ingress are opposite in point of view of the client
        let program = load_program(&mut ebpf, &args.interface, TcAttachType::Egress)?;
        programs.push(program);
        log::info!(
            "loaded ingress program, bandwidth={bandwidth}Mbit/s, burst={}KB",
            args.burst
        );
    }

    if let Some(bandwidth) = args.egress {
        let link = load_program(&mut ebpf, &args.interface, TcAttachType::Ingress)?;
        programs.push(link);
        log::info!(
            "loaded egress program, bandwidth={bandwidth}Mbit/s, burst={}KB",
            args.burst
        );
    }

    cleanup::cleanup_states_indefinitly(&mut ebpf)
}

fn load_program(
    ebpf: &mut Ebpf,
    interface: &str,
    attach_type: TcAttachType,
) -> anyhow::Result<SchedClassifierLinkId> {
    let entry_point = cal_entry_point(attach_type);
    let program: &mut SchedClassifier = ebpf
        .program_mut(entry_point)
        .with_context(|| format!("no '{entry_point}' entry point in ebpf code"))?
        .try_into()?;
    program.load().with_context(|| "couldn't load program")?;
    // incase the kernel is old and uses netlink we must have a parent qdisc
    if !is_using_tcx() && tc::qdisc_add_clsact(interface).is_ok() {
        log::info!("added clsact qdisc for {interface}");
    }
    let link = program
        .attach(interface, attach_type)
        .with_context(|| "couldn't attach program to interface")?;
    Ok(link)
}

fn cleanup_netlink_qdiscs(interface: &str) {
    let _ = tc::qdisc_detach_program(
        interface,
        TcAttachType::Egress,
        cal_entry_point(TcAttachType::Egress),
    );
    let _ = tc::qdisc_detach_program(
        interface,
        TcAttachType::Ingress,
        cal_entry_point(TcAttachType::Ingress),
    );
}

fn cal_entry_point(attach_type: TcAttachType) -> &'static str {
    match attach_type {
        TcAttachType::Ingress => "wgtc_ingress",
        TcAttachType::Egress => "wgtc_egress",
        _ => unreachable!(),
    }
}

fn is_using_tcx() -> bool {
    KernelVersion::current().is_ok_and(|version| version > KernelVersion::new(6, 6, 0))
}

#[cfg(feature = "ebpf_log")]
fn setup_ebpf_logger(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    use nix::poll::PollTimeout;
    use nix::poll::{PollFd, PollFlags};
    use std::os::fd::{AsRawFd, BorrowedFd};

    let mut logger =
        aya_log::EbpfLogger::init(ebpf).with_context(|| "couldn't init ebpf logger")?;
    log::info!("enabled ebpf logger");

    std::thread::spawn(move || {
        let fd = unsafe { BorrowedFd::borrow_raw(logger.as_raw_fd()) };
        let mut fds = [PollFd::new(fd, PollFlags::POLLIN)];
        loop {
            if nix::poll::poll(&mut fds, PollTimeout::NONE).is_ok_and(|nready| nready >= 1) {
                logger.flush();
            }
        }
    });
    Ok(())
}
