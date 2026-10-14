//! Owner-only filesystem protection.
//!
//! The dummy backend stores private software keys in a SQLite database. This
//! module makes sure that, once written, neither the database nor its
//! containing directory can be read by any other user.
//!
//! * **Unix** — directories become `0700`, files and sockets `0600`.
//! * **Windows** — files and directories get a protected, owner-only DACL.
//!
//! Neither mode makes the keys encrypted or hardware-backed; they are still
//! software keys at security level `file`. This is exactly the protection the
//! architecture document attributes to the dummy store.

#[cfg(unix)]
mod imp {
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    /// Create `path` (and parents) and force mode `0700`.
    pub fn ensure_dir(path: &Path) -> io::Result<()> {
        std::fs::create_dir_all(path)?;
        set_mode(path, 0o700)
    }

    /// Force mode `0600` on an existing file.
    pub fn restrict_file(path: &Path) -> io::Result<()> {
        set_mode(path, 0o600)
    }

    /// Force mode `0600` on a socket.
    pub fn restrict_socket(path: &Path) -> io::Result<()> {
        set_mode(path, 0o600)
    }

    fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }
}

#[cfg(windows)]
mod imp {
    use std::io;
    use std::path::Path;

    use crate::winutil;

    /// Create `path` (and parents) and apply a protected owner-only DACL.
    pub fn ensure_dir(path: &Path) -> io::Result<()> {
        std::fs::create_dir_all(path)?;
        winutil::set_owner_only(path)
    }

    /// Apply a protected owner-only DACL to an existing file.
    pub fn restrict_file(path: &Path) -> io::Result<()> {
        winutil::set_owner_only(path)
    }

    /// Named pipes carry their own DACL at creation; nothing to do here.
    pub fn restrict_socket(_path: &Path) -> io::Result<()> {
        Ok(())
    }
}

pub use imp::{ensure_dir, restrict_file, restrict_socket};
