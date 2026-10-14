//! `tpmd` command-line entry point.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use tpmd::Config;
use tpmd_client::KeyRequest;
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
    /// Ask a running agent whether it is reachable, and what it can do.
    ///
    /// A silent background agent still has to be observable; this is the
    /// first-class answer to "is it running?", on every platform.
    Status(StatusArgs),
}

#[derive(Args)]
struct StatusArgs {
    /// Endpoint to reach. Defaults to the per-user endpoint, then the system
    /// endpoint (Unix only for an explicit path).
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Namespace to ask as. Keys are scoped by namespace, so this only changes
    /// which namespace the agent reports.
    #[arg(long, default_value = "tpmd-status")]
    namespace: String,
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
        Command::Status(args) => status(args),
    }
}

/// Report whether an agent answers, and what it says about itself.
///
/// This deliberately goes through the published client library rather than a
/// private path: the answer a user gets here is the same contract an
/// application gets, so "it works" means the client works too.
fn status(args: StatusArgs) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("tpmd: cannot start the async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };

    let namespace = args.namespace;
    let socket = args.socket;
    runtime.block_on(async move {
        let client = match socket {
            Some(path) => {
                let endpoint = tpmd_ipc::Endpoint::unix_socket(path);
                tpmd_client::Client::connect(&endpoint, &namespace, KeyRequest::None).await
            }
            // No explicit endpoint: try the per-user one, then the system one.
            None => tpmd_client::Client::connect_candidates(&namespace, KeyRequest::None).await,
        };

        let mut client = match client {
            Ok(client) => client,
            Err(error) => {
                eprintln!("agent     : unreachable ({error})");
                return ExitCode::FAILURE;
            }
        };

        let status = match client.status().await {
            Ok(status) => status,
            Err(error) => {
                eprintln!("agent     : reachable, but status failed ({error})");
                return ExitCode::FAILURE;
            }
        };

        let levels = status
            .levels
            .iter()
            .map(|level| level.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!("agent         : listening");
        println!("daemon        : {}", status.daemon);
        println!("backend       : {}", status.backend);
        println!("principal     : {}", status.principal);
        println!("namespace     : {}", status.namespace);
        println!(
            "levels        : [{levels}] (achieved {})",
            status.default_level
        );
        println!("default floor : {}", status.default_min_security);
        ExitCode::SUCCESS
    })
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
