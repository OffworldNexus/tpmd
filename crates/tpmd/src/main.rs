//! `tpmd` command-line entry point.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use tpmd::Config;
use tpmd_ipc::{Endpoint, SocketAccess};
use tpmd_proto::SecurityLevel;
use tracing_subscriber::EnvFilter;

/// The state directory a shared system daemon uses by default.
///
/// Distinct from the per-user data directory because one store serves many
/// principals; the deployment owns creating it (see `docs/architecture.md`).
const SYSTEM_STATE_DIR: &str = "/var/lib/tpmd";

#[derive(Parser)]
#[command(name = "tpmd", version, about = "Local key agent")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the agent.
    Serve(ServeArgs),
}

#[derive(Args)]
struct ServeArgs {
    /// Endpoint to bind. On Unix, a socket path; defaults to the per-user
    /// endpoint (`$XDG_RUNTIME_DIR/tpmd/tpmd.sock` or equivalent), or the
    /// system endpoint (`/run/tpmd.sock`) in system mode.
    #[arg(long)]
    socket: Option<PathBuf>,
    /// State directory for the backends. Defaults to the platform data dir,
    /// or `/var/lib/tpmd` in system mode.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Security floor advertised to clients (enforcement follows each
    /// client's request, which must opt in with `allow_below_floor`).
    #[arg(long, default_value = "sealed", value_name = "LEVEL")]
    min_key_security: String,
    /// Force a specific backend by name. Fails if that backend is not built
    /// for this platform or cannot be used on this host.
    #[arg(long, value_name = "NAME")]
    backend: Option<String>,
    /// Run as a shared system daemon: the system endpoint (`/run/tpmd.sock`),
    /// a socket any local user may connect to (mode 0666), and the system
    /// state directory. Defaults on when running as root.
    #[arg(long, conflicts_with = "user")]
    system: bool,
    /// Run as a per-user daemon: the per-user endpoint (mode 0600) and the
    /// per-user state directory. Forces user mode even when running as root.
    #[arg(long)]
    user: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    match cli.command {
        Command::Serve(args) => serve(args),
    }
}

fn serve(args: ServeArgs) -> ExitCode {
    let Some(default_min_security) = SecurityLevel::parse(&args.min_key_security) else {
        eprintln!(
            "tpmd: invalid --min-key-security {:?} (expected file, keyring, sealed or hardware)",
            args.min_key_security
        );
        return ExitCode::FAILURE;
    };

    // Explicit flags win; otherwise root implies a shared system daemon.
    let system_mode = if args.system {
        true
    } else if args.user {
        false
    } else {
        tpmd_ipc::effective_uid() == Some(0)
    };
    let socket_access = if system_mode {
        SocketAccess::LocalUsers
    } else {
        SocketAccess::Owner
    };

    let endpoint = if let Some(path) = args.socket {
        Endpoint::unix_socket(path)
    } else if system_mode {
        match Endpoint::system() {
            Some(endpoint) => endpoint,
            None => {
                eprintln!("tpmd: this platform has no system-wide endpoint");
                return ExitCode::FAILURE;
            }
        }
    } else {
        match Endpoint::user() {
            Ok(endpoint) => endpoint,
            Err(error) => {
                eprintln!("tpmd: cannot determine the user endpoint: {error}");
                return ExitCode::FAILURE;
            }
        }
    };

    let default_state_dir = if system_mode {
        PathBuf::from(SYSTEM_STATE_DIR)
    } else {
        tpmd::state_dir()
    };

    let config = Config {
        endpoint,
        state_dir: args.state_dir.unwrap_or(default_state_dir),
        default_min_security,
        backend: args.backend,
        socket_access,
    };

    eprintln!(
        "tpmd: {} mode, endpoint {}, state {}",
        if system_mode { "system" } else { "user" },
        config.endpoint.display(),
        config.state_dir.display()
    );

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("tpmd: cannot start the async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };

    runtime.block_on(async move {
        if let Err(error) = tpmd::run(config).await {
            eprintln!("tpmd: {error}");
            std::process::exit(1);
        }
    });

    ExitCode::SUCCESS
}
