//! `tpmd` command-line entry point.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use tpmd::Config;
use tpmd_client::KeyRequest;
use tpmd_ipc::{Endpoint, SocketAccess};
use tpmd_proto::{BackendSelection, SecurityLevel, StoreState};
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
    /// Inspect or change which backend this machine uses.
    ///
    /// The choice is made once and kept: it never changes by itself, because a
    /// different store means a different key, and a device that silently re-keys
    /// is a device that has to pair again. Changing it is an administrator's
    /// decision, and this is the verb that makes it.
    Backend(BackendArgs),
}

#[derive(Args)]
struct BackendArgs {
    /// State directory holding the record. Defaults to the platform data dir.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    #[command(subcommand)]
    action: Option<BackendAction>,
}

#[derive(Subcommand)]
enum BackendAction {
    /// Print what this machine chose, and why. The default when none is given.
    Show,
    /// Choose a backend deliberately, replacing whatever was chosen before.
    Set {
        /// Backend to use: must be one this build has (see `tpmd backend`).
        name: String,
        /// Confirm the change. Required: it can re-key the device.
        #[arg(long)]
        yes: bool,
    },
    /// Forget the choice, so the next start runs the ladder again.
    Clear,
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
        Command::Backend(args) => backend(args),
    }
}

/// Read, change or forget this machine's backend choice.
///
/// The record lives in the shared store, so this opens the same store the daemon
/// does — same file, same protections — rather than a private sidecar.
fn backend(args: BackendArgs) -> ExitCode {
    let state_dir = args.state_dir.unwrap_or_else(tpmd::state_dir);
    let action = args.action.unwrap_or(BackendAction::Show);

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

    runtime.block_on(async move {
        let db = match tpmd_store::open(&state_dir).await {
            Ok(db) => db,
            Err(error) => {
                eprintln!(
                    "tpmd: cannot open the store at {}: {error}",
                    state_dir.display()
                );
                return ExitCode::FAILURE;
            }
        };
        let store = tpmd::selection::SelectionStore::new(db);
        match action {
            BackendAction::Show => show_selection(&store).await,
            BackendAction::Set { name, yes } => set_selection(&store, &name, yes).await,
            BackendAction::Clear => clear_selection(&store).await,
        }
    })
}

/// Print what this machine chose, and why.
async fn show_selection(store: &tpmd::selection::SelectionStore) -> ExitCode {
    match store.read().await {
        Err(error) => {
            eprintln!("tpmd: cannot read the selection record: {error}");
            ExitCode::FAILURE
        }
        Ok(None) => {
            println!("selection : none yet — the next start will choose one");
            println!("            (a choice is recorded the first time the store serves)");
            ExitCode::SUCCESS
        }
        Ok(Some(record)) => {
            println!("backend   : {}", record.backend);
            println!(
                "chosen    : {} — {}",
                age_of(record.chosen_unix),
                record.reason
            );
            if !record.skipped.is_empty() {
                println!("passed over:");
                for (name, reason) in &record.skipped {
                    println!("            {name}: {reason}");
                }
            }
            println!(
                "change it : tpmd backend set <name>   (re-keys the device: applications may need to pair again)"
            );
            println!("forget it : tpmd backend clear");
            ExitCode::SUCCESS
        }
    }
}

/// Change the choice, deliberately.
async fn set_selection(
    store: &tpmd::selection::SelectionStore,
    name: &str,
    confirmed: bool,
) -> ExitCode {
    // Refuse a name this build does not have: the daemon would refuse to start
    // afterwards, and better to say so now than to leave a machine that will not
    // boot its agent.
    let factories = tpmd::registry::builtin_factories();
    if !factories.iter().any(|factory| factory.name() == name) {
        eprintln!(
            "tpmd: {name} is not a backend this build has (built: {})",
            tpmd::registry::built_names(&factories)
        );
        return ExitCode::FAILURE;
    }

    if !confirmed {
        eprintln!("tpmd: changing the backend can change the key store this machine uses.");
        eprintln!("tpmd: a key made with a different store is a different identity, so");
        eprintln!("tpmd: applications may have to pair with this device again.");
        eprintln!("tpmd: pass --yes to confirm.");
        return ExitCode::FAILURE;
    }

    let record = tpmd::selection::SelectionRecord {
        backend: name.to_owned(),
        chosen_unix: tpmd::selection::now_unix(),
        reason: "set by an administrator".to_owned(),
        // Nothing was passed over: this was chosen, not derived.
        skipped: Vec::new(),
    };
    match store.write(&record).await {
        Ok(()) => {
            println!("selection : {name} (takes effect at the next start)");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("tpmd: cannot write the selection record: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Forget the choice.
async fn clear_selection(store: &tpmd::selection::SelectionStore) -> ExitCode {
    match store.clear().await {
        Ok(()) => {
            println!("selection : cleared — the next start will choose again");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("tpmd: cannot clear the selection record: {error}");
            ExitCode::FAILURE
        }
    }
}

/// How long ago something happened, in words.
///
/// The record is read by a human deciding whether it is still what they meant, so
/// "3 hours ago" is more use than an epoch second — and gives an obvious cue when
/// it says "8 months ago".
fn age_of(unix: i64) -> String {
    let now = tpmd::selection::now_unix();
    let seconds = (now - unix).max(0);
    let (count, unit) = match seconds {
        s if s < 90 => (s, "second"),
        s if s < 90 * 60 => (s / 60, "minute"),
        s if s < 36 * 3600 => (s / 3600, "hour"),
        s => (s / 86_400, "day"),
    };
    format!("{count} {unit}{} ago", if count == 1 { "" } else { "s" })
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
        println!("store         : {}", describe_store(&status.store));
        println!(
            "selection     : {} — {}",
            status.selection.backend,
            describe_selection(&status.selection)
        );
        ExitCode::SUCCESS
    })
}

/// The store's state, in one line.
fn describe_store(state: &StoreState) -> String {
    match state {
        StoreState::Open => "open".to_owned(),
        StoreState::Closed(closed) => format!("closed ({:?}: {})", closed.code, closed.message),
    }
}

/// The choice, in one line — and what an administrator could adopt instead.
///
/// The suggestion is *information*: adopting a stronger backend re-keys the
/// device, so it is never the daemon's decision to make.
fn describe_selection(selection: &BackendSelection) -> String {
    let mut text = match (selection.chosen_unix, &selection.reason) {
        (Some(chosen), Some(reason)) => format!("chosen {} — {reason}", age_of(chosen)),
        // A machine whose store has not served since it was chosen records
        // nothing, which is deliberate: a store that merely happened to be locked
        // at startup must not settle the machine on a weaker one.
        _ => "not recorded yet (recorded the first time the store serves)".to_owned(),
    };
    if let Some(stronger) = &selection.stronger_available {
        text.push_str(&format!(
            "\n              note: a stronger backend is available now ({stronger});\n              `tpmd backend set {stronger}` adopts it, re-keying the device"
        ));
    }
    text
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
