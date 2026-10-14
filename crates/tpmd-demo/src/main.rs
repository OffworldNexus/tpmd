//! A toy consumer for tpmd.
//!
//! It walks the whole key life-cycle Tunnel Weaver needs, with a simulated
//! relay, and never touches Tunnel Weaver itself: discover capabilities; watch
//! the default `sealed` floor enforced (refused by the dummy, already met on a
//! TPM); provision a key at the strongest level the selected backend offers;
//! enrol the public key with a simulated relay; sign a handshake transcript and
//! verify it independently; permit an agent restart and resume the same
//! identity; destroy and re-create; and show representative failures.
//!
//! `run` is self-contained: it starts and restarts the real `tpmd` binary
//! (found next to this executable), so a few commands demonstrate everything.
//! `run --sudo` starts that agent as root instead (Linux only), which is the
//! usual way to reach the TPM backend without changing your shell's identity.

use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as ProcCommand, Stdio};
use std::time::Duration;

use clap::{Parser, Subcommand};
use p256::ecdsa::VerifyingKey;
use p256::ecdsa::signature::Verifier as _;
use tpmd_client::{Client, ClientError};
use tpmd_ipc::Endpoint;
use tpmd_proto::{
    Algorithm, ErrorCode, ErrorDetail, KeyId, KeyInfo, KeyOutcome, KeyRequest, ProvisionRequest,
    RejectCode, SecurityLevel, Welcome,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// The daemon's default floor; the demo opts below it explicitly.
const DEFAULT_FLOOR: SecurityLevel = SecurityLevel::Sealed;

#[derive(Parser)]
#[command(name = "tpmd-demo", version, about = "Toy consumer for tpmd")]
struct Cli {
    /// Endpoint to connect to. Defaults to the per-user endpoint.
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    /// Application namespace to connect as.
    #[arg(long, global = true, default_value = "tpmd-demo")]
    namespace: String,
    /// State directory (used by `run`, which spawns the agent).
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Full self-contained life-cycle: spawns and restarts the agent.
    Run {
        /// Start the agent as root through `sudo`, so the Linux TPM backend can
        /// open `/dev/tpmrm*` (`tss:tss 0660`). Linux only.
        #[arg(long)]
        sudo: bool,
    },
    /// Connect without a key and print the capability announce.
    Probe,
    /// Create a key at the file floor and print its fingerprint.
    Provision,
    /// Sign a UTF-8 message with a key fingerprint; print the signature hex.
    Sign {
        /// The key fingerprint (33-byte SEC1 compressed, hex).
        #[arg(value_parser = parse_key_id)]
        key_id: KeyId,
        /// The message to sign.
        message: String,
    },
    /// Print a key's metadata.
    Describe {
        /// The key fingerprint (hex).
        #[arg(value_parser = parse_key_id)]
        key_id: KeyId,
    },
    /// Destroy a key.
    Destroy {
        /// The key fingerprint (hex).
        #[arg(value_parser = parse_key_id)]
        key_id: KeyId,
    },
    /// Print the daemon status for this namespace.
    Status,
    /// Demonstrate representative failures against a running agent.
    Errors,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(dispatch(cli))
}

async fn dispatch(cli: Cli) -> Result<()> {
    let Cli {
        socket,
        namespace,
        state_dir,
        command,
    } = cli;
    match command {
        Command::Run { sudo } => run_lifecycle(state_dir, sudo).await,
        Command::Probe => {
            let mut client = connect_probe(&socket, &namespace).await?;
            print_welcome(client.welcome());
            let status = client.status().await?;
            println!("status    : {status:?}");
            Ok(())
        }
        Command::Provision => {
            let endpoint = resolve_endpoint(&socket)?;
            let request = ProvisionRequest {
                algorithm: Algorithm::EcdsaP256Sha256,
                min_security: DEFAULT_FLOOR,
                allow_below_floor: true,
            };
            let client =
                Client::connect(&endpoint, &namespace, KeyRequest::Create(request)).await?;
            println!("{}", outcome_info(client.key_outcome())?.key_id.to_hex());
            Ok(())
        }
        Command::Sign { key_id, message } => {
            let mut client = connect_probe(&socket, &namespace).await?;
            let signature = client.sign(key_id, message.as_bytes()).await?;
            println!("{}", signature.to_hex());
            Ok(())
        }
        Command::Describe { key_id } => {
            let mut client = connect_probe(&socket, &namespace).await?;
            let info = client.describe(key_id).await?;
            println!("{info:?}");
            Ok(())
        }
        Command::Destroy { key_id } => {
            let mut client = connect_probe(&socket, &namespace).await?;
            client.destroy(key_id).await?;
            println!("destroyed {key_id}");
            Ok(())
        }
        Command::Status => {
            let mut client = connect_probe(&socket, &namespace).await?;
            println!("{:#?}", client.status().await?);
            Ok(())
        }
        Command::Errors => demonstrate_errors(&socket, &namespace).await,
    }
}

/// The full self-contained walk-through.
async fn run_lifecycle(state_dir: Option<PathBuf>, sudo: bool) -> Result<()> {
    if sudo && !cfg!(target_os = "linux") {
        return Err("--sudo is only available on Linux".into());
    }

    // Hold the tempdir alive for the whole run so a restart reuses the store.
    let (workdir, _temporary) = match state_dir {
        Some(dir) => (dir, None),
        None => {
            let temporary = tempfile::tempdir()?;
            let path = temporary.path().to_path_buf();
            (path, Some(temporary))
        }
    };
    let namespace = "tpmd-demo";
    println!("work dir  : {}", workdir.display());

    // 1. Start the agent.
    let mut agent = Agent::start(&workdir, sudo).await?;
    let endpoint = agent.endpoint.clone();
    println!("\n[1] started agent at {}", endpoint.display());

    // 2. Discover capabilities.
    {
        let mut probe = Client::connect(&endpoint, namespace, KeyRequest::None).await?;
        println!("[2] capability announce:");
        print_welcome(probe.welcome());
        let _ = probe.status().await?;
    }

    // 3. The default `sealed` floor must refuse the dummy store.
    let sealed = ProvisionRequest {
        algorithm: Algorithm::EcdsaP256Sha256,
        min_security: DEFAULT_FLOOR,
        allow_below_floor: false,
    };
    match Client::connect(&endpoint, namespace, KeyRequest::Create(sealed)).await {
        Err(ClientError::Rejected {
            code: RejectCode::IncompatiblePolicy,
            detail:
                Some(ErrorDetail::Floor {
                    required,
                    available,
                }),
            ..
        }) => println!(
            "[3] sealed floor correctly refused (required {required}, available {available})"
        ),
        // A backend that already reaches the floor is not a failure: a usable
        // TPM satisfies `sealed` without consent, and says so.
        Ok(_) => println!("[3] sealed floor already met by this backend (no refusal)"),
        Err(other) => return Err(format!("expected a floor refusal, got {other:?}").into()),
    }

    // 4. Provision at `file`, with explicit consent.
    let file_floor = ProvisionRequest {
        algorithm: Algorithm::EcdsaP256Sha256,
        min_security: DEFAULT_FLOOR,
        allow_below_floor: true,
    };
    let mut client =
        Client::connect(&endpoint, namespace, KeyRequest::Create(file_floor.clone())).await?;
    let info = outcome_info(client.key_outcome())?.clone();
    println!(
        "[4] provisioned key {} at level {}",
        info.key_id.to_hex(),
        info.security_level
    );
    let fingerprint = info.key_id;

    // 5. Enrol the public key with a simulated relay.
    let relay = SimulatedRelay::enrol(&workdir, &info);
    println!("[5] relay enrolled fingerprint {}", relay.key_id.to_hex());

    // 6. Sign a Tunnel Weaver-style transcript and verify it independently.
    let transcript = weaver_transcript();
    let signature = client.sign(fingerprint, &transcript).await?;
    relay.verify(&transcript, &signature)?;
    println!(
        "[6] signature {} verified against the enrolled key",
        signature.to_hex()
    );
    // Negative control: a mutated transcript must fail.
    let mut mutated = transcript.clone();
    mutated[0] ^= 0x01;
    if relay.verify(&mutated, &signature).is_ok() {
        return Err("a mutated transcript wrongly verified".into());
    }
    println!("    mutated transcript correctly rejected");
    // RFC 6979 makes a *software* signer deterministic. A hardware key signs
    // inside the TPM with a fresh nonce, so a second signature differs — but it
    // must still verify.
    let again = client.sign(fingerprint, &transcript).await?;
    relay.verify(&transcript, &again)?;
    if again == signature {
        println!("    re-signing is deterministic (software signer)");
    } else if info.security_level == SecurityLevel::Hardware {
        println!("    re-signing produced a different, still-valid signature (hardware nonce)");
    } else {
        return Err("a software signer should be deterministic".into());
    }

    // 7. Restart the agent and resume the same identity.
    drop(client);
    agent.stop();
    agent = Agent::start(&workdir, sudo).await?;
    println!("[7] restarted agent");
    let mut client = Client::connect(
        &agent.endpoint,
        namespace,
        KeyRequest::ResumeOrCreate {
            key_id: fingerprint,
            provision: file_floor.clone(),
        },
    )
    .await?;
    let resumed = outcome_info(client.key_outcome())?;
    if resumed.key_id != fingerprint {
        return Err("the identity changed across a restart".into());
    }
    println!("    resumed the same identity {}", resumed.key_id.to_hex());

    // 8. Destroy, then re-create explicitly.
    client.destroy(fingerprint).await?;
    println!("[8] destroyed {fingerprint}");
    let client = Client::connect(
        &agent.endpoint,
        namespace,
        KeyRequest::ResumeOrCreate {
            key_id: fingerprint,
            provision: file_floor,
        },
    )
    .await?;
    let recreated = outcome_info(client.key_outcome())?;
    if recreated.key_id == fingerprint {
        return Err("a destroyed key was unexpectedly reused".into());
    }
    println!(
        "    re-created as a new identity {}",
        recreated.key_id.to_hex()
    );

    // 9. Stop the agent: it must now be unreachable.
    drop(client);
    agent.stop();
    match Client::connect(&agent.endpoint, namespace, KeyRequest::None).await {
        Err(ClientError::Unavailable { .. }) => {
            println!("[9] stopped agent; unreachable as expected");
        }
        Err(other) => {
            return Err(format!("expected the agent to be unreachable, got {other:?}").into());
        }
        Ok(_) => return Err("expected the agent to be unreachable, but it connected".into()),
    }

    println!("\nhappy path complete");
    Ok(())
}

async fn demonstrate_errors(socket: &Option<PathBuf>, namespace: &str) -> Result<()> {
    // Unreachable agent: a socket that does not exist.
    let bogus = Endpoint::unix_socket(std::env::temp_dir().join("tpmd-demo-missing.sock"));
    match Client::connect(&bogus, namespace, KeyRequest::None).await {
        Err(ClientError::Unavailable { .. }) => println!("unreachable agent   -> reported"),
        Err(other) => return Err(format!("expected unreachable, got {other:?}").into()),
        Ok(_) => return Err("expected unreachable, but connected".into()),
    }

    let endpoint = resolve_endpoint(socket)?;

    // Rejected floor: sealed without consent.
    match Client::connect(
        &endpoint,
        namespace,
        KeyRequest::Create(ProvisionRequest {
            algorithm: Algorithm::EcdsaP256Sha256,
            min_security: DEFAULT_FLOOR,
            allow_below_floor: false,
        }),
    )
    .await
    {
        Err(ClientError::Rejected {
            code: RejectCode::IncompatiblePolicy,
            ..
        }) => println!("rejected floor      -> reported"),
        // A backend that already meets the floor cannot demonstrate a refusal.
        Ok(_) => println!("rejected floor      -> not applicable: this backend meets the floor"),
        Err(other) => return Err(format!("expected a floor refusal, got {other:?}").into()),
    }

    // Unknown key: sign with a fingerprint the daemon has never seen.
    let mut client = connect_probe(socket, namespace).await?;
    let unknown = KeyId::P256([0xaa; 33]);
    match client.sign(unknown, b"whatever").await {
        Err(ClientError::Request {
            code: ErrorCode::UnknownKey,
            ..
        }) => println!("unknown key         -> reported"),
        Err(other) => return Err(format!("expected unknown_key, got {other:?}").into()),
        Ok(_) => return Err("expected unknown_key, but the signature succeeded".into()),
    }

    Ok(())
}

/// A relay that only remembers one enrolled public key, in memory.
struct SimulatedRelay {
    key_id: KeyId,
}

impl SimulatedRelay {
    fn enrol(_workdir: &Path, info: &KeyInfo) -> Self {
        Self {
            key_id: info.key_id,
        }
    }

    fn verify(&self, message: &[u8], signature: &tpmd_proto::Signature) -> Result<()> {
        let verifying =
            VerifyingKey::from_sec1_bytes(self.key_id.as_bytes()).map_err(|e| e.to_string())?;
        let sig =
            p256::ecdsa::Signature::from_slice(signature.as_bytes()).map_err(|e| e.to_string())?;
        verifying
            .verify(message, &sig)
            .map_err(|e| format!("signature verification failed: {e}").into())
    }
}

/// The exact transcript Tunnel Weaver's mux signs, for realism.
fn weaver_transcript() -> Vec<u8> {
    let mut transcript = Vec::with_capacity(88);
    transcript.extend_from_slice(b"weaver-mux-v1");
    transcript.extend_from_slice(&[0x01; 32]);
    transcript.extend_from_slice(&[0x02; 32]);
    transcript.extend_from_slice(b"example.com");
    transcript
}

/// A spawned `tpmd` process plus the endpoint to reach it.
struct Agent {
    child: Child,
    endpoint: Endpoint,
    /// Whether the daemon was started through `sudo` (and is therefore a
    /// grandchild of this process). `--sudo` is Linux-only, so the field is too.
    #[cfg(target_os = "linux")]
    via_sudo: bool,
}

impl Agent {
    async fn start(workdir: &Path, sudo: bool) -> Result<Self> {
        let binary = daemon_binary().ok_or(
            "cannot find the `tpmd` binary next to `tpmd-demo`; run `cargo build --workspace` first",
        )?;

        let mut command = if sudo {
            // Run the daemon in a session of its own. Without `setsid`, `sudo`
            // takes over this process's controlling terminal: it writes a
            // stray NUL byte and clears ONLCR, which leaves the caller's
            // terminal printing a staircase. A detached session has no
            // controlling terminal to hijack — which also means `sudo` cannot
            // prompt for a password, so `--sudo` expects passwordless sudo.
            let mut command = ProcCommand::new("setsid");
            command.arg("sudo").arg(binary);
            command
        } else {
            ProcCommand::new(binary)
        };
        command
            .arg("serve")
            .arg("--state-dir")
            .arg(workdir)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(unix)]
        {
            let socket = workdir.join("tpmd.sock");
            command.arg("--socket").arg(&socket);
        }
        let child = command.spawn()?;

        let endpoint = resolve_run_endpoint(workdir)?;
        // Wait until the agent answers a probe handshake.
        for _ in 0..100 {
            if Client::connect(&endpoint, "tpmd-demo-readiness", KeyRequest::None)
                .await
                .is_ok()
            {
                return Ok(Self {
                    child,
                    endpoint,
                    #[cfg(target_os = "linux")]
                    via_sudo: sudo,
                });
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err(if sudo {
            "the agent did not become ready in time (is `sudo` usable without a password prompt?)"
                .into()
        } else {
            "the agent did not become ready in time".into()
        })
    }

    fn stop(&mut self) {
        // A daemon started through `sudo` is a grandchild: `Child::kill` sends
        // SIGKILL to `sudo` alone and would orphan a root daemon still holding
        // the socket, so send SIGTERM instead — `sudo` relays it to the daemon.
        #[cfg(target_os = "linux")]
        if self.via_sudo {
            let _ = ProcCommand::new("kill")
                .arg("-TERM")
                .arg(self.child.id().to_string())
                .status();
            let _ = self.child.wait();
            return;
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn daemon_binary() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let name = if cfg!(windows) { "tpmd.exe" } else { "tpmd" };
    let candidate = exe.parent()?.join(name);
    candidate.exists().then_some(candidate)
}

fn resolve_run_endpoint(workdir: &Path) -> Result<Endpoint> {
    #[cfg(unix)]
    {
        Ok(Endpoint::unix_socket(workdir.join("tpmd.sock")))
    }
    #[cfg(windows)]
    {
        let _ = workdir;
        Ok(Endpoint::user()?)
    }
}

fn resolve_endpoint(socket: &Option<PathBuf>) -> Result<Endpoint> {
    match socket {
        Some(path) => Ok(Endpoint::unix_socket(path)),
        None => Ok(Endpoint::user()?),
    }
}

async fn connect_probe(socket: &Option<PathBuf>, namespace: &str) -> Result<Client> {
    let endpoint = resolve_endpoint(socket)?;
    Ok(Client::connect(&endpoint, namespace, KeyRequest::None).await?)
}

fn outcome_info(outcome: &KeyOutcome) -> Result<&KeyInfo> {
    match outcome {
        KeyOutcome::Created(info) | KeyOutcome::Resumed(info) => Ok(info),
        KeyOutcome::None => Err("the handshake did not establish a key".into()),
    }
}

fn print_welcome(welcome: &Welcome) {
    let capabilities = &welcome.capabilities;
    println!("  principal : {}", welcome.principal);
    println!(
        "  daemon    : {} (backend {})",
        capabilities.daemon, capabilities.backend
    );
    println!("  protocol  : v{}", welcome.version);
    println!("  algorithms: {:?}", capabilities.algorithms);
    println!(
        "  levels    : {:?} (achieved {:?})",
        capabilities.levels, capabilities.default_level
    );
    println!(
        "  encodings : key {} / signature {}",
        capabilities.key_id_encoding, capabilities.signature_encoding
    );
}

fn parse_key_id(value: &str) -> std::result::Result<KeyId, String> {
    let bytes = hex::decode(value).map_err(|e| format!("invalid hex: {e}"))?;
    let array: [u8; 33] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("expected 33 bytes, got {}", bytes.len()))?;
    Ok(KeyId::P256(array))
}
