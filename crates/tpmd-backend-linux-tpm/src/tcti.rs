//! TCTI: the TPM 2.0 command transport over a character device.
//!
//! The kernel's resource manager exposes `/dev/tpmrm0`: you write a complete
//! TPM2 command packet and read back a complete response packet, with the RM
//! handling context save/load, transient-slot pressure and `TPM2_Startup`
//! behind the file descriptor. That is all the "TCTI" we need — no libtss2,
//! no `unsafe`, no `ioctl`.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
/// Environment variable naming an exact TPM device to use.
///
/// An explicit choice is authoritative: if it cannot be opened, the backend
/// reports that path's error rather than silently using another device.
pub const DEVICE_ENV: &str = "TPMD_TPM_DEVICE";

/// How many resource-manager device nodes to probe (`/dev/tpmrm0`…).
///
/// A machine can host more than one TPM, and the kernel numbers them; rather
/// than assume `tpmrm0` exists (or is the right one), the candidate list is
/// scanned in order and the first device that opens wins.
const MAX_DEVICE_INDEX: u32 = 16;

/// Candidate device nodes, most preferred first.
///
/// The resource-manager nodes (`tpmrm*`) are preferred because the RM gives
/// each open descriptor its own context space; a bare `/dev/tpm0` is a last
/// resort with no such isolation.
#[must_use]
pub fn candidates() -> Vec<PathBuf> {
    if let Some(explicit) = std::env::var_os(DEVICE_ENV) {
        return vec![PathBuf::from(explicit)];
    }
    let mut paths: Vec<PathBuf> = (0..MAX_DEVICE_INDEX)
        .map(|index| PathBuf::from(format!("/dev/tpmrm{index}")))
        .collect();
    paths.push(PathBuf::from("/dev/tpm0"));
    paths
}

/// Open the first candidate device that works.
///
/// Returns the path it settled on — the backend logs it, so an operator can
/// tell which of several TPMs is in use.
pub fn open_usable() -> Result<(PathBuf, Tcti), String> {
    let paths = candidates();
    let mut first_error = None;
    for path in &paths {
        match Tcti::open(path) {
            Ok(tcti) => return Ok((path.clone(), tcti)),
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(format!("{}: {error}", path.display()));
                }
            }
        }
    }
    Err(format!(
        "no usable TPM device (tried {} candidate(s); first error: {})",
        paths.len(),
        first_error.unwrap_or_else(|| "none".to_owned())
    ))
}

/// Upper bound on a command or response packet.
///
/// The largest of our commands (a `Create` with an ECC parent) is a few
/// hundred bytes; the largest response (a `CreatePrimary`) is under a
/// kilobyte. A 4 KiB ceiling is generous while still refusing to trust a
/// device-claimed length.
const MAX_PACKET: usize = 4096;

/// A single open connection to the TPM resource manager.
pub struct Tcti {
    file: File,
}

impl Tcti {
    /// Open the device. Failure here (absent node, missing permission) means
    /// "no usable TPM", which is exactly what [`crate::LinuxTpmBackend::can_be_used`]
    /// reports.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        Ok(Self { file })
    }

    /// Send one command and read exactly one response.
    ///
    /// The RM guarantees a response for every accepted command, so a partial
    /// read is normal and handled by `read_exact`.
    pub fn transmit(&mut self, command: &[u8]) -> std::io::Result<Vec<u8>> {
        if command.len() < 10 || command.len() > MAX_PACKET {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("command size {} is out of range", command.len()),
            ));
        }

        self.file.write_all(command)?;
        self.file.flush()?;

        let mut header = [0u8; 10];
        self.file.read_exact(&mut header)?;
        let size = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
        if !(10..=MAX_PACKET).contains(&size) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("device claimed a response of {size} bytes"),
            ));
        }

        let mut response = vec![0u8; size];
        response[..10].copy_from_slice(&header);
        self.file.read_exact(&mut response[10..])?;
        Ok(response)
    }
}
