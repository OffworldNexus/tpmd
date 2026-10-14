//! `tpmd` command-line entry point.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use tpmd::Config;
use tpmd_ipc::Endpoint;
use tpmd_proto::SecurityLevel;
use tracing_subscriber::EnvFilter;

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
    /// endpoint (`$XDG_RUNTIME_DIR/tpmd/tpmd.sock` or equivalent).
    #[arg(long)]
    socket: Option<PathBuf>,
    /// State directory for the backend. Defaults to the platform data dir.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Security floor advertised to clients (enforcement follows each
    /// client's request, which must opt in with `allow_below_floor`).
    #[arg(long, default_value = "sealed", value_name = "LEVEL")]
    min_key_security: String,
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

    let endpoint = match args.socket {
        Some(path) => Endpoint::unix_socket(path),
        None => match Endpoint::user() {
            Ok(endpoint) => endpoint,
            Err(error) => {
                eprintln!("tpmd: cannot determine the user endpoint: {error}");
                return ExitCode::FAILURE;
            }
        },
    };

    let config = Config {
        endpoint,
        state_dir: args.state_dir.unwrap_or_else(tpmd::state_dir),
        default_min_security,
    };

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
