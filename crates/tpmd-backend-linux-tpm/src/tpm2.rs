//! TPM 2.0 command marshalling and response parsing.
//!
//! This module is deliberately device-*free*: it builds command packets and
//! parses response packets as byte strings, so every layout here is unit
//! tested on a machine with no TPM. The device I/O lives in [`crate::tcti`].
//!
//! Only the subset the backend needs is implemented, hand-rolled against the
//! TPM 2.0 Part 2 structures (the libtss2 sources and `tpm2-tools` were used
//! as the reference). The rules that matter and are easy to get wrong:
//!
//! * A `TPMT_PUBLIC` is **not** a `TPM2B`; a `TPM2B_PUBLIC` is.
//! * Union members are encoded by their selector: `TPMT_SYM_DEF_OBJECT` with
//!   `algorithm == TPM_ALG_NULL` is two bytes, not six.
//! * A password session is `TPM_RS_PW` with an empty nonce and empty HMAC.
//! * `TPMT_SIGNATURE` for ECDSA is `sigAlg | hash | TPM2B r | TPM2B s`, and
//!   the TPM strips leading zeros from `r` and `s`, so both must be left
//!   padded to 32 bytes to satisfy the wire contract.

use crate::tcti::Tcti;

/// A TPM failure, classified by what the caller can do about it.
#[derive(Debug, thiserror::Error)]
pub enum TpmError {
    /// The device could not be reached or the exchange failed at the I/O
    /// layer: a transient condition, retryable once the TPM is back.
    #[error("TPM device unavailable: {0}")]
    Unavailable(String),
    /// The TPM answered `TPM_RC_INTEGRITY`: the object's integrity check
    /// failed, which is what a firmware reset or `TPM2_Clear` looks like from
    /// here. The wrapped key is not recoverable — this is key loss, not a bug.
    #[error("TPM integrity error: {0}")]
    Integrity(String),
    /// The TPM answered `TPM_RC_HANDLE`/`TPM_RC_REFERENCE`: a handle went
    /// stale (the cached parent was invalidated). Retryable by recreating the
    /// parent.
    #[error("TPM handle error: {0}")]
    Handle(String),
    /// The TPM answered `TPM_RC_ATTRIBUTES`: the requested object attributes
    /// are inconsistent with the parent. A programming error, not a device
    /// condition.
    #[error("TPM attribute error: {0}")]
    Attributes(String),
    /// Any other non-zero return code.
    #[error("TPM command failed ({rc:#06x}): {detail}")]
    Command {
        /// The raw return code.
        rc: u32,
        /// Human-readable form.
        detail: String,
    },
    /// The response did not have the shape the spec promises.
    #[error("TPM protocol error: {0}")]
    Protocol(String),
}

/// Tag values.
const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_ST_SESSIONS: u16 = 0x8002;
const TPM_ST_HASHCHECK: u16 = 0x8024;

/// Command codes.
const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
const TPM_CC_CREATE: u32 = 0x0000_0153;
const TPM_CC_LOAD: u32 = 0x0000_0157;
const TPM_CC_SIGN: u32 = 0x0000_015d;
const TPM_CC_UNSEAL: u32 = 0x0000_015e;
const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;

/// Handles.
const TPM_RH_OWNER: u32 = 0x4000_0001;
const TPM_RH_NULL: u32 = 0x4000_0007;
const TPM_RS_PW: u32 = 0x4000_0009;

/// Algorithms.
const TPM_ALG_AES: u16 = 0x0006;
const TPM_ALG_SHA256: u16 = 0x000b;
const TPM_ALG_KEYEDHASH: u16 = 0x0008;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_ECDSA: u16 = 0x0018;
const TPM_ALG_ECC: u16 = 0x0023;
const TPM_ALG_CFB: u16 = 0x0043;
const TPM_ECC_NIST_P256: u16 = 0x0003;

/// `TPMA_OBJECT` bits we care about.
const ATTR_FIXED_TPM: u32 = 0x0000_0002;
const ATTR_FIXED_PARENT: u32 = 0x0000_0010;
const ATTR_SENSITIVE_DATA_ORIGIN: u32 = 0x0000_0020;
const ATTR_USER_WITH_AUTH: u32 = 0x0000_0040;
const ATTR_NO_DA: u32 = 0x0000_0400;
const ATTR_RESTRICTED: u32 = 0x0001_0000;
const ATTR_DECRYPT: u32 = 0x0002_0000;
const ATTR_SIGN: u32 = 0x0004_0000;

/// The storage parent: restricted decryption key that wraps children with
/// AES-128-CFB. Exactly the template the WVR-141 proof established works on
/// this firmware TPM.
const ATTR_STORAGE_PARENT: u32 = ATTR_FIXED_TPM
    | ATTR_FIXED_PARENT
    | ATTR_SENSITIVE_DATA_ORIGIN
    | ATTR_USER_WITH_AUTH
    | ATTR_NO_DA
    | ATTR_RESTRICTED
    | ATTR_DECRYPT;

/// A signing child: non-exportable, non-duplicable, signs only.
const ATTR_SIGNING_CHILD: u32 = ATTR_FIXED_TPM
    | ATTR_FIXED_PARENT
    | ATTR_SENSITIVE_DATA_ORIGIN
    | ATTR_USER_WITH_AUTH
    | ATTR_NO_DA
    | ATTR_SIGN;

/// A sealed object: holds our software scalar, moveable nowhere, no origin
/// claim (the sensitive data came from *us*, not the TPM).
const ATTR_SEALED_OBJECT: u32 =
    ATTR_FIXED_TPM | ATTR_FIXED_PARENT | ATTR_USER_WITH_AUTH | ATTR_NO_DA;

/// Return codes (base values, before the index/P bits).
const TPM_RC_ATTRIBUTES: u32 = 0x082;
const TPM_RC_HANDLE: u32 = 0x08b;
const TPM_RC_INTEGRITY: u32 = 0x09f;

/// The wrapped blobs of a freshly created object.
pub struct CreatedObject {
    /// `TPM2B_PRIVATE`, the wrapped sensitive half.
    pub private: Vec<u8>,
    /// `TPM2B_PUBLIC`, the public half (needed again to `Load`).
    pub public: Vec<u8>,
}

/// An open connection to a TPM, with the deterministic storage parent cached.
pub struct Tpm {
    tcti: Tcti,
    primary: Option<u32>,
}

impl Tpm {
    /// Wrap an already-open transport.
    pub fn from_tcti(tcti: Tcti) -> Self {
        Self {
            tcti,
            primary: None,
        }
    }

    /// Forget the cached parent handle.
    ///
    /// Called when the TPM reports a stale handle: the next operation creates
    /// a fresh (identical, because the template and hierarchy seed are fixed)
    /// primary and the wrapped children still load under it.
    pub fn forget_parent(&mut self) {
        self.primary = None;
    }

    /// The storage parent, created on first use and cached.
    ///
    /// It is deterministic: `TPM2_CreatePrimary` derives it from the
    /// owner-hierarchy seed and the template below, so the same parent comes
    /// back after a daemon or process restart. That is what makes it safe to
    /// persist only the wrapped child blobs.
    pub fn storage_parent(&mut self) -> Result<u32, TpmError> {
        if let Some(handle) = self.primary {
            return Ok(handle);
        }
        let handle = self.create_primary_storage()?;
        self.primary = Some(handle);
        Ok(handle)
    }

    fn create_primary_storage(&mut self) -> Result<u32, TpmError> {
        let mut w = Writer::command(TPM_ST_SESSIONS, TPM_CC_CREATE_PRIMARY);
        w.u32(TPM_RH_OWNER);
        w.password_session();
        w.sensitive_create_empty();
        w.in_public_ecc(ATTR_STORAGE_PARENT, SymScheme::Storage, KeyScheme::Null);
        w.u16(0); // outsideInfo
        w.u32(0); // creationPCR
        let raw = self.send(w)?;
        let mut reply = Reply::parse(&raw)?;
        reply.handle()
    }

    /// Create the non-exportable signing child under `parent`.
    pub fn create_signing_child(&mut self, parent: u32) -> Result<CreatedObject, TpmError> {
        let mut w = Writer::command(TPM_ST_SESSIONS, TPM_CC_CREATE);
        w.u32(parent);
        w.password_session();
        w.sensitive_create_empty();
        w.in_public_ecc(ATTR_SIGNING_CHILD, SymScheme::Null, KeyScheme::EcdsaSha256);
        w.u16(0); // outsideInfo
        w.u32(0); // creationPCR
        let raw = self.send(w)?;
        self.parse_created(&raw)
    }

    /// Create a sealed `KEYEDHASH` object holding `secret`, wrapped by
    /// `parent`. This is the `sealed` level: the scalar is in the TPM only at
    /// rest.
    pub fn create_sealed_object(
        &mut self,
        parent: u32,
        secret: &[u8],
    ) -> Result<CreatedObject, TpmError> {
        let mut w = Writer::command(TPM_ST_SESSIONS, TPM_CC_CREATE);
        w.u32(parent);
        w.password_session();
        w.sensitive_create_with_data(secret);
        w.in_public_keyedhash();
        w.u16(0); // outsideInfo
        w.u32(0); // creationPCR
        let raw = self.send(w)?;
        self.parse_created(&raw)
    }

    /// Load a previously created object under `parent`.
    pub fn load(&mut self, parent: u32, private: &[u8], public: &[u8]) -> Result<u32, TpmError> {
        let mut w = Writer::command(TPM_ST_SESSIONS, TPM_CC_LOAD);
        w.u32(parent);
        w.password_session();
        w.buf(private);
        w.buf(public);
        let raw = self.send(w)?;
        let mut reply = Reply::parse(&raw)?;
        reply.handle()
    }

    /// Sign a **pre-computed** SHA-256 digest with the ECDSA key at `handle`.
    ///
    /// `inScheme` is `TPM_ALG_NULL`, so the key's own scheme (ECDSA/SHA-256)
    /// applies, and the empty `TPMT_TK_HASHCHECK` is accepted because the key
    /// is not `restricted`.
    pub fn sign_digest(&mut self, handle: u32, digest: &[u8]) -> Result<[u8; 64], TpmError> {
        let mut w = Writer::command(TPM_ST_SESSIONS, TPM_CC_SIGN);
        w.u32(handle);
        w.password_session();
        w.buf(digest);
        w.u16(TPM_ALG_NULL); // inScheme: use the key's scheme
        w.u16(TPM_ST_HASHCHECK);
        w.u32(TPM_RH_NULL);
        w.u16(0); // empty validation digest
        let raw = self.send(w)?;

        let mut reply = Reply::parse(&raw)?;
        reply.begin_params()?;
        let sig_alg = reply.u16()?;
        let _hash = reply.u16()?;
        if sig_alg != TPM_ALG_ECDSA {
            return Err(TpmError::Protocol(format!(
                "expected an ECDSA signature, got sigAlg {sig_alg:#06x}"
            )));
        }
        let r = reply.buf()?;
        let s = reply.buf()?;
        if r.len() > 32 || s.len() > 32 {
            return Err(TpmError::Protocol(format!(
                "ECDSA component wider than the curve: r={} s={}",
                r.len(),
                s.len()
            )));
        }
        let mut out = [0u8; 64];
        out[32 - r.len()..32].copy_from_slice(r);
        out[64 - s.len()..].copy_from_slice(s);
        Ok(out)
    }

    /// Unseal a sealed object, returning its sensitive data.
    pub fn unseal(&mut self, handle: u32) -> Result<Vec<u8>, TpmError> {
        let mut w = Writer::command(TPM_ST_SESSIONS, TPM_CC_UNSEAL);
        w.u32(handle);
        w.password_session();
        let raw = self.send(w)?;
        let mut reply = Reply::parse(&raw)?;
        reply.begin_params()?;
        Ok(reply.buf()?.to_vec())
    }

    /// Release a transient object handle.
    pub fn flush_context(&mut self, handle: u32) -> Result<(), TpmError> {
        let mut w = Writer::command(TPM_ST_NO_SESSIONS, TPM_CC_FLUSH_CONTEXT);
        w.u32(handle);
        let raw = self.send(w)?;
        Reply::parse(&raw).map(|_| ())
    }

    fn send(&mut self, writer: Writer) -> Result<Vec<u8>, TpmError> {
        let command = writer.finish();
        self.tcti
            .transmit(&command)
            .map_err(|e| TpmError::Unavailable(e.to_string()))
    }

    fn parse_created(&mut self, raw: &[u8]) -> Result<CreatedObject, TpmError> {
        let mut reply = Reply::parse(raw)?;
        reply.begin_params()?;
        let private = reply.buf()?.to_vec();
        let public = reply.buf()?.to_vec();
        Ok(CreatedObject { private, public })
    }
}

/// Extract the affine `(x, y)` coordinates of an ECC `TPMT_PUBLIC`.
///
/// Walks the variable-length fields the way the TPM encodes them, stopping at
/// `unique`. `x`/`y` come back as `TPM2B_ECC_PARAMETER` values, i.e. possibly
/// shorter than 32 bytes when the leading bytes happen to be zero.
pub fn ecc_public_point(public: &[u8]) -> Result<(Vec<u8>, Vec<u8>), TpmError> {
    let mut r = Reader::new(public);
    let kind = r.u16()?;
    let _name_alg = r.u16()?;
    let _attributes = r.u32()?;
    r.buf()?; // authPolicy

    match kind {
        TPM_ALG_ECC => {
            read_sym_def_object(&mut r)?;
            read_ecc_scheme(&mut r)?;
            let _curve = r.u16()?;
            read_kdf_scheme(&mut r)?;
        }
        TPM_ALG_KEYEDHASH => {
            read_keyedhash_scheme(&mut r)?;
            r.buf()?; // unique TPM2B_DIGEST
        }
        other => {
            return Err(TpmError::Protocol(format!(
                "unsupported public key type {other:#06x}"
            )));
        }
    }

    let x = r.buf()?.to_vec();
    let y = r.buf()?.to_vec();
    Ok((x, y))
}

fn read_sym_def_object(r: &mut Reader<'_>) -> Result<(), TpmError> {
    let algorithm = r.u16()?;
    if algorithm != TPM_ALG_NULL {
        let _key_bits = r.u16()?;
        let _mode = r.u16()?;
    }
    Ok(())
}

fn read_ecc_scheme(r: &mut Reader<'_>) -> Result<(), TpmError> {
    let scheme = r.u16()?;
    if scheme != TPM_ALG_NULL {
        // Only the ECDSA/ECDH shape (a single hash algorithm) is expected.
        let _hash = r.u16()?;
    }
    Ok(())
}

fn read_kdf_scheme(r: &mut Reader<'_>) -> Result<(), TpmError> {
    let scheme = r.u16()?;
    if scheme != TPM_ALG_NULL {
        let _hash = r.u16()?;
    }
    Ok(())
}

fn read_keyedhash_scheme(r: &mut Reader<'_>) -> Result<(), TpmError> {
    let scheme = r.u16()?;
    if scheme != TPM_ALG_NULL {
        let _hash = r.u16()?;
    }
    Ok(())
}

/// Classify a non-zero return code into the [`TpmError`] taxonomy.
///
/// The index and `P` bits are masked off so `TPM_RC_ATTRIBUTES` with any
/// parameter number lands in [`TpmError::Attributes`].
fn classify(rc: u32) -> TpmError {
    let base = if rc & 0x080 != 0 {
        0x080 | (rc & 0x03f)
    } else {
        rc & !(0x0f00 | 0x040)
    };
    let detail = format!("TPM return code {rc:#06x}");
    match base {
        TPM_RC_INTEGRITY => TpmError::Integrity(detail),
        TPM_RC_HANDLE => TpmError::Handle(detail),
        TPM_RC_ATTRIBUTES => TpmError::Attributes(detail),
        _ => TpmError::Command { rc, detail },
    }
}

/// How the parent wraps children.
enum SymScheme {
    Null,
    Storage,
}

/// The child's signing scheme.
enum KeyScheme {
    Null,
    EcdsaSha256,
}

/// A write-once command builder.
struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn command(tag: u16, code: u32) -> Self {
        let mut w = Self { buf: Vec::new() };
        w.u16(tag);
        w.u32(0); // commandSize, patched in `finish`
        w.u32(code);
        w
    }

    fn u16(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    /// A length-prefixed `TPM2B_*`.
    fn buf(&mut self, bytes: &[u8]) {
        self.u16(bytes.len() as u16);
        self.buf.extend_from_slice(bytes);
    }

    /// An empty `TPM2B_SENSITIVE_CREATE`.
    ///
    /// The inner `TPMT_SENSITIVE_CREATE` is two empty `TPM2B`s, so its size is
    /// **4**, not 0 — a zero size is rejected with `TPM_RC_SIZE`.
    fn sensitive_create_empty(&mut self) {
        self.u16(4);
        self.u16(0); // userAuth
        self.u16(0); // data
    }

    /// A `TPM2B_SENSITIVE_CREATE` carrying `data` as the sensitive payload.
    fn sensitive_create_with_data(&mut self, data: &[u8]) {
        self.u16(4 + data.len() as u16);
        self.u16(0); // userAuth
        self.buf(data);
    }

    /// One `TPM_RS_PW` password session with an empty auth value.
    fn password_session(&mut self) {
        const SESSION_LEN: u32 = 4 + 2 + 1 + 2;
        self.u32(SESSION_LEN); // authSize
        self.u32(TPM_RS_PW);
        self.u16(0); // nonce
        self.buf.push(0); // session attributes
        self.u16(0); // hmac
    }

    /// A `TPM2B_PUBLIC` for an ECC key, length-prefixed.
    fn in_public_ecc(&mut self, attributes: u32, symmetric: SymScheme, scheme: KeyScheme) {
        let mut public = Writer::bare();
        public.public_ecc(attributes, symmetric, scheme);
        self.buf(&public.buf);
    }

    /// A `TPM2B_PUBLIC` for a sealed `KEYEDHASH` object, length-prefixed.
    fn in_public_keyedhash(&mut self) {
        let mut public = Writer::bare();
        public.public_keyedhash();
        self.buf(&public.buf);
    }

    fn bare() -> Self {
        Self { buf: Vec::new() }
    }

    /// A `TPMT_PUBLIC` for an ECC key (no length prefix).
    fn public_ecc(&mut self, attributes: u32, symmetric: SymScheme, scheme: KeyScheme) {
        self.u16(TPM_ALG_ECC);
        self.u16(TPM_ALG_SHA256);
        self.u32(attributes);
        self.u16(0); // authPolicy
        match symmetric {
            SymScheme::Null => self.u16(TPM_ALG_NULL),
            SymScheme::Storage => {
                self.u16(TPM_ALG_AES);
                self.u16(128);
                self.u16(TPM_ALG_CFB);
            }
        }
        match scheme {
            KeyScheme::Null => self.u16(TPM_ALG_NULL),
            KeyScheme::EcdsaSha256 => {
                self.u16(TPM_ALG_ECDSA);
                self.u16(TPM_ALG_SHA256);
            }
        }
        self.u16(TPM_ECC_NIST_P256);
        self.u16(TPM_ALG_NULL); // kdf
        // `unique` for an ECC key is a TPMS_ECC_POINT: two TPM2Bs (x and y),
        // both empty in a creation template.
        self.u16(0);
        self.u16(0);
    }

    /// A `TPMT_PUBLIC` for a sealed `KEYEDHASH` object.
    fn public_keyedhash(&mut self) {
        self.u16(TPM_ALG_KEYEDHASH);
        self.u16(TPM_ALG_SHA256);
        self.u32(ATTR_SEALED_OBJECT);
        self.u16(0); // authPolicy
        self.u16(TPM_ALG_NULL); // scheme
        self.u16(0); // unique
    }

    fn finish(mut self) -> Vec<u8> {
        let size = self.buf.len() as u32;
        self.buf[2..6].copy_from_slice(&size.to_be_bytes());
        self.buf
    }
}

/// A read-once response parser positioned after the 10-byte header.
struct Reply<'a> {
    reader: Reader<'a>,
    sessions: bool,
}

impl<'a> Reply<'a> {
    fn parse(raw: &'a [u8]) -> Result<Self, TpmError> {
        let mut reader = Reader::new(raw);
        let tag = reader.u16()?;
        let size = reader.u32()? as usize;
        let rc = reader.u32()?;
        if size != raw.len() {
            return Err(TpmError::Protocol(format!(
                "response length {size} does not match the {} bytes received",
                raw.len()
            )));
        }
        if rc != 0 {
            return Err(classify(rc));
        }
        Ok(Self {
            reader,
            sessions: tag == TPM_ST_SESSIONS,
        })
    }

    /// Read a response handle.
    fn handle(&mut self) -> Result<u32, TpmError> {
        self.reader.u32()
    }

    /// Skip the `parameterSize` a session response carries.
    fn begin_params(&mut self) -> Result<(), TpmError> {
        if self.sessions {
            let _parameter_size = self.reader.u32()?;
        }
        Ok(())
    }

    fn u16(&mut self) -> Result<u16, TpmError> {
        self.reader.u16()
    }

    fn buf(&mut self) -> Result<&'a [u8], TpmError> {
        self.reader.buf()
    }
}

/// A bounds-checked big-endian reader.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], TpmError> {
        let end = self.pos.checked_add(count).ok_or_else(|| {
            TpmError::Protocol("length overflow while parsing a TPM response".into())
        })?;
        if end > self.data.len() {
            return Err(TpmError::Protocol(format!(
                "response truncated: wanted {count} bytes at offset {}, only {} available",
                self.pos,
                self.data.len() - self.pos
            )));
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u16(&mut self) -> Result<u16, TpmError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, TpmError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn buf(&mut self) -> Result<&'a [u8], TpmError> {
        let len = self.u16()? as usize;
        self.take(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_header_carries_the_size_tag_and_code() {
        let mut w = Writer::command(TPM_ST_SESSIONS, TPM_CC_UNSEAL);
        w.u32(0x8000_0001);
        w.password_session();
        let command = w.finish();

        assert_eq!(&command[0..2], &[0x80, 0x02], "tag");
        assert_eq!(
            u32::from_be_bytes([command[2], command[3], command[4], command[5]]) as usize,
            command.len(),
            "commandSize must cover the whole packet"
        );
        assert_eq!(&command[6..10], &[0x00, 0x00, 0x01, 0x5e], "commandCode");
    }

    #[test]
    fn in_public_is_a_length_prefixed_tpm2b_public() {
        let mut w = Writer::command(TPM_ST_SESSIONS, TPM_CC_CREATE_PRIMARY);
        w.in_public_ecc(ATTR_STORAGE_PARENT, SymScheme::Storage, KeyScheme::Null);
        let command = w.finish();
        // First the TPM2B size, then the TPMT_PUBLIC.
        assert_eq!(
            u16::from_be_bytes([command[10], command[11]]) as usize,
            command.len() - 12,
            "the prefix must cover exactly the TPMT_PUBLIC"
        );
        assert_eq!(&command[12..14], &[0x00, 0x23], "TPM_ALG_ECC");
    }

    #[test]
    fn an_empty_sensitive_area_is_four_bytes_not_zero() {
        let mut w = Writer::command(TPM_ST_SESSIONS, TPM_CC_CREATE_PRIMARY);
        w.sensitive_create_empty();
        let command = w.finish();
        // Right after the header: the TPM2B size, then the two empty TPM2Bs.
        assert_eq!(&command[10..], &[0x00, 0x04, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn a_password_session_is_nine_bytes_of_the_documented_shape() {
        let mut w = Writer::command(TPM_ST_SESSIONS, TPM_CC_SIGN);
        w.password_session();
        let command = w.finish();
        // header (10) + authSize (4)
        assert_eq!(
            u32::from_be_bytes([command[10], command[11], command[12], command[13]]),
            9
        );
        assert_eq!(&command[14..18], &TPM_RS_PW.to_be_bytes(), "session handle");
        assert_eq!(&command[18..20], &[0, 0], "empty nonce");
        assert_eq!(command[20], 0, "session attributes");
        assert_eq!(&command[21..23], &[0, 0], "empty hmac");
    }

    #[test]
    fn storage_parent_template_is_the_proven_one() {
        let mut w = Writer::command(TPM_ST_SESSIONS, TPM_CC_CREATE_PRIMARY);
        w.public_ecc(ATTR_STORAGE_PARENT, SymScheme::Storage, KeyScheme::Null);
        let public = w.finish();
        let body = &public[10..];
        // type, nameAlg, attributes
        assert_eq!(&body[0..2], &[0x00, 0x23], "TPM_ALG_ECC");
        assert_eq!(&body[2..4], &[0x00, 0x0b], "SHA-256");
        assert_eq!(&body[4..8], &ATTR_STORAGE_PARENT.to_be_bytes());
        assert_eq!(
            u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
            0x0003_0472
        );
    }

    #[test]
    fn symmetric_null_is_two_bytes_and_aes_is_six() {
        let mut null = Writer::command(TPM_ST_SESSIONS, TPM_CC_CREATE_PRIMARY);
        null.public_ecc(0, SymScheme::Null, KeyScheme::Null);
        let mut aes = Writer::command(TPM_ST_SESSIONS, TPM_CC_CREATE_PRIMARY);
        aes.public_ecc(0, SymScheme::Storage, KeyScheme::Null);
        // AES adds keyBits and mode on top of the algorithm selector.
        assert_eq!(aes.finish().len() - null.finish().len(), 4);
    }

    #[test]
    fn a_short_r_and_s_are_left_padded() {
        // sigAlg, hash, r (2 bytes), s (3 bytes)
        let mut raw = Vec::new();
        raw.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        raw.extend_from_slice(&0u32.to_be_bytes()); // size placeholder
        raw.extend_from_slice(&0u32.to_be_bytes()); // rc
        raw.extend_from_slice(&0u32.to_be_bytes()); // parameterSize
        raw.extend_from_slice(&TPM_ALG_ECDSA.to_be_bytes());
        raw.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        raw.extend_from_slice(&2u16.to_be_bytes());
        raw.extend_from_slice(&[0xaa, 0xbb]);
        raw.extend_from_slice(&3u16.to_be_bytes());
        raw.extend_from_slice(&[0x01, 0x02, 0x03]);
        let size = raw.len() as u32;
        raw[2..6].copy_from_slice(&size.to_be_bytes());

        let mut reply = Reply::parse(&raw).unwrap();
        reply.begin_params().unwrap();
        let sig_alg = reply.u16().unwrap();
        let _hash = reply.u16().unwrap();
        let r = reply.buf().unwrap();
        let s = reply.buf().unwrap();
        assert_eq!(sig_alg, TPM_ALG_ECDSA);

        let mut out = [0u8; 64];
        out[32 - r.len()..32].copy_from_slice(r);
        out[64 - s.len()..].copy_from_slice(s);
        assert_eq!(&out[0..30], &[0u8; 30]);
        assert_eq!(&out[30..32], &[0xaa, 0xbb]);
        assert_eq!(&out[32..61], &[0u8; 29]);
        assert_eq!(&out[61..64], &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn an_error_response_is_classified_by_its_base_code() {
        // TPM_RC_ATTRIBUTES with parameter number 2, as the firmware TPM
        // returned for a signing primary.
        assert!(matches!(classify(0x2c2), TpmError::Attributes(_)));
        assert!(matches!(classify(0x1df), TpmError::Integrity(_)));
        assert!(matches!(classify(0x18b), TpmError::Handle(_)));
        assert!(matches!(classify(0x0000_0142), TpmError::Command { .. }));
    }

    #[test]
    fn an_ecc_public_point_is_extracted_from_a_tpmt_public() {
        // type, nameAlg, attributes, authPolicy, symmetric(AES/128/CFB),
        // scheme(NULL), curve, kdf(NULL), unique x, unique y
        let mut public = Vec::new();
        public.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
        public.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        public.extend_from_slice(&ATTR_SIGNING_CHILD.to_be_bytes());
        public.extend_from_slice(&0u16.to_be_bytes());
        public.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        public.extend_from_slice(&TPM_ALG_ECDSA.to_be_bytes());
        public.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        public.extend_from_slice(&TPM_ECC_NIST_P256.to_be_bytes());
        public.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        public.extend_from_slice(&2u16.to_be_bytes());
        public.extend_from_slice(&[0xde, 0xad]);
        public.extend_from_slice(&1u16.to_be_bytes());
        public.extend_from_slice(&[0xbe]);

        let (x, y) = ecc_public_point(&public).unwrap();
        assert_eq!(x, vec![0xde, 0xad]);
        assert_eq!(y, vec![0xbe]);
    }

    #[test]
    fn a_truncated_response_is_a_protocol_error() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        raw.extend_from_slice(&10u32.to_be_bytes());
        raw.extend_from_slice(&0u32.to_be_bytes());
        let mut reply = Reply::parse(&raw).unwrap();
        assert!(matches!(reply.handle(), Err(TpmError::Protocol(_))));
    }
}
