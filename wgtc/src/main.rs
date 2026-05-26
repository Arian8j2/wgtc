use anyhow::{Context, ensure};
use aya::{
    Ebpf,
    programs::{SchedClassifier, TcAttachType},
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
    #[arg(short, long, default_value = "64")]
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

    if let Some(bandwidth) = args.ingress {
        load_program(
            &mut ebpf,
            "wgtc_ingress",
            &args.interface,
            TcAttachType::Ingress,
        )?;
        log::info!(
            "loaded ingress program, bandwidth={bandwidth}Mbit/s, burst={}KB",
            args.burst
        );
    }

    if let Some(bandwidth) = args.egress {
        load_program(
            &mut ebpf,
            "wgtc_egress",
            &args.interface,
            TcAttachType::Egress,
        )?;
        log::info!(
            "loaded egress program, bandwidth={bandwidth}Mbit/s, burst={}KB",
            args.burst
        );
    }

    cleanup::cleanup_states_indefinitly(&mut ebpf)
}

fn load_program(
    ebpf: &mut Ebpf,
    entry_point: &str,
    interface: &str,
    attach_type: TcAttachType,
) -> anyhow::Result<()> {
    let program: &mut SchedClassifier = ebpf
        .program_mut(entry_point)
        .with_context(|| format!("no '{entry_point}' entry point in ebpf code"))?
        .try_into()?;
    program.load().with_context(|| "couldn't load program")?;
    program
        .attach(interface, attach_type)
        .context("failed to attach program to interface")?;
    Ok(())
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
