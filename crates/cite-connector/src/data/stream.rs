//! `cite-stream-v1`: an encrypted, seekable container for backup dumps.
//!
//! A 128-byte header carries the data key wrapped under the node key; the body is a run of independently
//! sealed 64 KiB chunks. The chunk number and a last-chunk flag are part of each nonce, so chunks cannot be
//! reordered and a truncated stream is detected, and chunk `i` sits at a fixed offset so any range can be
//! decrypted without reading what precedes it.
//!
//! Header (big endian): magic `CITEBK01` (8) | version 1 | algorithm 1 | reserved u16 | kid (8) |
//! nonce prefix (7) | pad (1) | data-key nonce (12) | wrapped data key (48) | chunk size u32 |
//! plaintext length u64 | zero padding to 128.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::path::Path;

use cite_core::atomic::write_atomic_in;
use cite_core::confined::{FileName, TrustedDir};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::seal::{Keyring, open_with, random, seal_with};
use crate::{ConnectorError, Result};

pub const HEADER_LEN: usize = 128;
pub const CHUNK_SIZE: usize = 65_536;
const TAG_LEN: usize = 16;
const ENC_CHUNK: u64 = (CHUNK_SIZE + TAG_LEN) as u64;
const MAGIC: &[u8; 8] = b"CITEBK01";
const VERSION: u8 = 1;
const ALG_CHACHA20_POLY1305: u8 = 1;
const HEADER_MARKER_SUFFIX: &str = ".hdr.new";
const DEK_LEN: usize = 32;
const PREFIX_LEN: usize = 7;
// Reads while decrypting a whole stream go through this much plaintext at a time.
const STREAM_STEP: u64 = 1 << 20;

fn internal(msg: impl Into<String>) -> ConnectorError {
    ConnectorError::Internal(msg.into())
}

fn core(err: cite_core::Error) -> ConnectorError {
    internal(err.to_string())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Where chunk `index` starts in the file.
pub fn encrypted_chunk_offset(index: u64) -> u64 {
    HEADER_LEN as u64 + index * ENC_CHUNK
}

// A stream of zero bytes still has one (empty) chunk, which carries the last flag.
fn chunk_count(plain_len: u64) -> u64 {
    plain_len.div_ceil(CHUNK_SIZE as u64).max(1)
}

fn stored_len(plain_len: u64) -> u64 {
    HEADER_LEN as u64 + plain_len + chunk_count(plain_len) * TAG_LEN as u64
}

fn chunk_nonce(prefix: &[u8; PREFIX_LEN], index: u64, last: bool) -> Result<[u8; 12]> {
    let counter = u32::try_from(index).map_err(|_| internal("the stream has too many chunks"))?;
    let mut nonce = [0u8; 12];
    nonce[..PREFIX_LEN].copy_from_slice(prefix);
    nonce[PREFIX_LEN..PREFIX_LEN + 4].copy_from_slice(&counter.to_be_bytes());
    nonce[11] = u8::from(last);
    Ok(nonce)
}

#[derive(Clone)]
struct Header {
    kid: [u8; 8],
    prefix: [u8; PREFIX_LEN],
    dek_nonce: [u8; 12],
    wrapped: [u8; 48],
    plain_len: u64,
}

impl Header {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..8].copy_from_slice(MAGIC);
        out[8] = VERSION;
        out[9] = ALG_CHACHA20_POLY1305;
        out[12..20].copy_from_slice(&self.kid);
        out[20..27].copy_from_slice(&self.prefix);
        out[28..40].copy_from_slice(&self.dek_nonce);
        out[40..88].copy_from_slice(&self.wrapped);
        out[88..92].copy_from_slice(&(CHUNK_SIZE as u32).to_be_bytes());
        out[92..100].copy_from_slice(&self.plain_len.to_be_bytes());
        out
    }

    fn decode(raw: &[u8; HEADER_LEN]) -> Result<Self> {
        let bad = |why: &str| internal(format!("not a valid backup file: {why}"));
        if &raw[..8] != MAGIC {
            return Err(bad("wrong magic"));
        }
        if raw[8] != VERSION || raw[9] != ALG_CHACHA20_POLY1305 {
            return Err(bad("unsupported version or algorithm"));
        }
        if raw[10] != 0 || raw[11] != 0 || raw[27] != 0 || raw[100..].iter().any(|b| *b != 0) {
            return Err(bad("reserved bytes are set"));
        }
        let chunk_size = u32::from_be_bytes(raw[88..92].try_into().map_err(|_| bad("short"))?);
        if chunk_size as usize != CHUNK_SIZE {
            return Err(bad("unsupported chunk size"));
        }
        Ok(Self {
            kid: raw[12..20].try_into().map_err(|_| bad("short"))?,
            prefix: raw[20..27].try_into().map_err(|_| bad("short"))?,
            dek_nonce: raw[28..40].try_into().map_err(|_| bad("short"))?,
            wrapped: raw[40..88].try_into().map_err(|_| bad("short"))?,
            plain_len: u64::from_be_bytes(raw[92..100].try_into().map_err(|_| bad("short"))?),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSummary {
    pub plaintext_len: u64,
    /// Lower-case hex SHA-256 of the plaintext.
    pub sha256: String,
    /// Bytes on disk, header and tags included.
    pub stored_len: u64,
}

#[derive(PartialEq, Eq)]
enum WriteMode {
    Fresh,
    Sequential,
    Random,
}

/// Writes a new stream. Use either `write_all` (in order) or `write_chunk_at` (any order), not both.
pub struct StreamWriter {
    file: File,
    dek: Zeroizing<[u8; DEK_LEN]>,
    backup_id: String,
    header: Header,
    mode: WriteMode,
    // sequential mode
    buffer: Zeroizing<Vec<u8>>,
    next_index: u64,
    plain_len: u64,
    hasher: Sha256,
    // random mode: index -> (plaintext length, last flag)
    chunks: BTreeMap<u64, (usize, bool)>,
}

impl StreamWriter {
    /// Creates the file exclusively (mode 0600); it is the caller's to remove if the stream is abandoned.
    pub fn create(path: &Path, keyring: &Keyring, backup_id: &str) -> Result<Self> {
        let dek = Zeroizing::new(random::<DEK_LEN>()?);
        let prefix = random::<PREFIX_LEN>()?;
        let (kid, dek_nonce, wrapped) = keyring.wrap_dek(backup_id, &dek)?;
        let header = Header {
            kid,
            prefix,
            dek_nonce,
            wrapped,
            plain_len: 0,
        };
        let (dir, name) = TrustedDir::split(path).map_err(core)?;
        let file = dir
            .create_new_rw(&name, 0o600)
            .map_err(|e| internal(format!("cannot create {}: {e}", path.display())))?;
        file.write_all_at(&header.encode(), 0)
            .map_err(|e| internal(format!("cannot write {}: {e}", path.display())))?;
        Ok(Self {
            file,
            dek,
            backup_id: backup_id.to_string(),
            header,
            mode: WriteMode::Fresh,
            buffer: Zeroizing::new(Vec::new()),
            next_index: 0,
            plain_len: 0,
            hasher: Sha256::new(),
            chunks: BTreeMap::new(),
        })
    }

    fn put_chunk(&self, index: u64, plain: &[u8], last: bool) -> Result<()> {
        let nonce = chunk_nonce(&self.header.prefix, index, last)?;
        let sealed = seal_with(&self.dek, nonce, self.backup_id.as_bytes(), plain)?;
        self.file
            .write_all_at(&sealed, encrypted_chunk_offset(index))
            .map_err(|e| internal(format!("cannot write the backup: {e}")))
    }

    /// Appends plaintext. A full chunk is held back until more data proves it is not the last.
    pub fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        if self.mode == WriteMode::Random {
            return Err(internal(
                "a stream is written in order or by chunk, not both",
            ));
        }
        self.mode = WriteMode::Sequential;
        self.hasher.update(bytes);
        self.plain_len += bytes.len() as u64;
        let mut buffer = std::mem::take(&mut self.buffer);
        buffer.extend_from_slice(bytes);
        let mut start = 0;
        let mut outcome = Ok(());
        while buffer.len() - start > CHUNK_SIZE {
            outcome = self.put_chunk(self.next_index, &buffer[start..start + CHUNK_SIZE], false);
            if outcome.is_err() {
                break;
            }
            self.next_index += 1;
            start += CHUNK_SIZE;
        }
        buffer.drain(..start);
        self.buffer = buffer;
        outcome
    }

    /// Seals one chunk at its own position, for imports whose chunks arrive out of order or twice.
    /// Every chunk but the last is exactly `CHUNK_SIZE` bytes; only a stream with no data has an empty last chunk.
    pub fn write_chunk_at(&mut self, index: u64, plain: &[u8], last: bool) -> Result<()> {
        if self.mode == WriteMode::Sequential {
            return Err(internal(
                "a stream is written in order or by chunk, not both",
            ));
        }
        if plain.len() > CHUNK_SIZE || (!last && plain.len() != CHUNK_SIZE) {
            return Err(ConnectorError::BadRequest(
                "a chunk holds 65536 bytes, except the last".into(),
            ));
        }
        if last && plain.is_empty() && index != 0 {
            return Err(ConnectorError::BadRequest(
                "only a stream with no data may end in an empty chunk".into(),
            ));
        }
        if let Some((&other, _)) = self.chunks.iter().find(|(i, (_, l))| *l && **i != index)
            && (last || index > other)
        {
            return Err(ConnectorError::Conflict(
                "the stream already has a different last chunk".into(),
            ));
        }
        self.mode = WriteMode::Random;
        self.put_chunk(index, plain, last)?;
        self.chunks.insert(index, (plain.len(), last));
        Ok(())
    }

    /// Finalises the header and returns the plaintext length, its SHA-256 and the stored size.
    pub fn finish(mut self) -> Result<StreamSummary> {
        let sha256 = if self.mode == WriteMode::Random {
            self.finish_random()?
        } else {
            let buffer = std::mem::take(&mut self.buffer);
            self.put_chunk(self.next_index, &buffer, true)?;
            hex(&std::mem::take(&mut self.hasher).finalize())
        };
        self.header.plain_len = self.plain_len;
        self.file
            .write_all_at(&self.header.encode(), 0)
            .map_err(|e| internal(format!("cannot write the backup header: {e}")))?;
        self.file
            .sync_all()
            .map_err(|e| internal(format!("cannot flush the backup: {e}")))?;
        let stored = stored_len(self.plain_len);
        let on_disk = self
            .file
            .metadata()
            .map_err(|e| internal(format!("cannot inspect the backup: {e}")))?
            .len();
        if on_disk != stored {
            return Err(internal(
                "the backup has a different size than its chunks imply",
            ));
        }
        Ok(StreamSummary {
            plaintext_len: self.plain_len,
            sha256,
            stored_len: stored,
        })
    }

    // Checks the chunks form one contiguous run ending in a single last chunk, then hashes the plaintext in order.
    fn finish_random(&mut self) -> Result<String> {
        let last = self
            .chunks
            .iter()
            .find(|(_, (_, l))| *l)
            .map(|(i, _)| *i)
            .ok_or_else(|| ConnectorError::Conflict("the last chunk has not arrived".into()))?;
        if self.chunks.len() as u64 != last + 1
            || !self.chunks.keys().copied().eq(0..=last)
            || self.chunks.iter().any(|(i, (_, l))| *l != (*i == last))
        {
            return Err(ConnectorError::Conflict(
                "chunks are missing or inconsistent".into(),
            ));
        }
        let last_len = self.chunks[&last].0 as u64;
        self.plain_len = last * CHUNK_SIZE as u64 + last_len;
        let mut hasher = Sha256::new();
        for index in 0..=last {
            let plain_len = self.chunks[&index].0;
            let mut ct = vec![0u8; plain_len + TAG_LEN];
            self.file
                .read_exact_at(&mut ct, encrypted_chunk_offset(index))
                .map_err(|e| internal(format!("cannot read the backup back: {e}")))?;
            let nonce = chunk_nonce(&self.header.prefix, index, index == last)?;
            let plain = open_with(&self.dek, nonce, self.backup_id.as_bytes(), &ct)?;
            hasher.update(&*plain);
        }
        Ok(hex(&hasher.finalize()))
    }
}

/// Random access to the plaintext of a finished stream.
pub struct StreamReader {
    file: File,
    dek: Zeroizing<[u8; DEK_LEN]>,
    backup_id: String,
    header: Header,
    stored_len: u64,
}

impl StreamReader {
    /// Unwraps the data key with the keyring and checks the file has the size its header implies. A header
    /// staged by an interrupted `rewrap_header` is used in preference to the one in the file.
    pub fn open(path: &Path, keyring: &Keyring, backup_id: &str) -> Result<Self> {
        let (dir, name) = TrustedDir::split(path).map_err(core)?;
        let (file, meta) = dir
            .open_regular(&name)
            .map_err(|e| internal(format!("cannot open {}: {e}", path.display())))?;
        let marker = marker_name(&name)?;
        let header = match read_marker(&dir, &marker)? {
            Some(staged) => staged,
            None => {
                let mut raw = [0u8; HEADER_LEN];
                file.read_exact_at(&mut raw, 0).map_err(|_| {
                    internal("not a valid backup file: it is shorter than its header")
                })?;
                Header::decode(&raw)?
            }
        };
        if meta.len() != stored_len(header.plain_len) {
            return Err(internal(
                "the backup is truncated or damaged: its size does not match its header",
            ));
        }
        let dek = keyring.unwrap_dek(backup_id, header.kid, header.dek_nonce, &header.wrapped)?;
        Ok(Self {
            file,
            dek,
            backup_id: backup_id.to_string(),
            stored_len: meta.len(),
            header,
        })
    }

    pub fn plaintext_len(&self) -> u64 {
        self.header.plain_len
    }

    pub fn stored_len(&self) -> u64 {
        self.stored_len
    }

    pub fn kid_hex(&self) -> String {
        hex(&self.header.kid)
    }

    fn read_chunk(&self, index: u64) -> Result<Zeroizing<Vec<u8>>> {
        let count = chunk_count(self.header.plain_len);
        let last = index + 1 == count;
        let plain_len = if last {
            (self.header.plain_len - index * CHUNK_SIZE as u64) as usize
        } else {
            CHUNK_SIZE
        };
        let mut ct = vec![0u8; plain_len + TAG_LEN];
        self.file
            .read_exact_at(&mut ct, encrypted_chunk_offset(index))
            .map_err(|e| internal(format!("cannot read the backup: {e}")))?;
        let nonce = chunk_nonce(&self.header.prefix, index, last)?;
        open_with(&self.dek, nonce, self.backup_id.as_bytes(), &ct).map_err(|_| {
            internal(format!(
                "the backup is damaged: chunk {index} failed authentication (altered, reordered, truncated or wrong backup id)"
            ))
        })
    }

    /// Appends plaintext bytes `[offset, offset + len)` to `out`, clipped at the end of the stream.
    /// An offset past the end is an error. The caller owns `out` and decides how it is cleared.
    pub fn read_range(&mut self, offset: u64, len: u64, out: &mut Vec<u8>) -> Result<()> {
        let total = self.header.plain_len;
        if offset > total {
            return Err(ConnectorError::BadRequest(
                "the range starts past the end of the backup".into(),
            ));
        }
        let end = offset.saturating_add(len).min(total);
        if offset == end {
            // an empty stream is one empty chunk; reading it is what proves it was not forged
            if total == 0 {
                self.read_chunk(0)?;
            }
            return Ok(());
        }
        out.reserve((end - offset) as usize);
        let chunk = CHUNK_SIZE as u64;
        for index in (offset / chunk)..=((end - 1) / chunk) {
            let plain = self.read_chunk(index)?;
            let base = index * chunk;
            let from = offset.saturating_sub(base) as usize;
            let to = (end - base).min(plain.len() as u64) as usize;
            out.extend_from_slice(&plain[from..to]);
        }
        Ok(())
    }

    /// Decrypts the whole stream into `out` and returns the SHA-256 of the plaintext as hex.
    pub fn copy_to(&mut self, out: &mut impl Write) -> Result<String> {
        let mut hasher = Sha256::new();
        let mut offset = 0u64;
        let mut piece = Zeroizing::new(Vec::<u8>::new());
        loop {
            piece.clear();
            self.read_range(offset, STREAM_STEP, &mut piece)?;
            hasher.update(&*piece);
            out.write_all(&piece)
                .map_err(|e| internal(format!("cannot write the decrypted data: {e}")))?;
            offset += STREAM_STEP;
            if offset >= self.header.plain_len {
                break;
            }
        }
        Ok(hex(&hasher.finalize()))
    }
}

fn marker_name(name: &FileName) -> Result<FileName> {
    FileName::new(format!("{name}{HEADER_MARKER_SUFFIX}"))
        .map_err(|e| internal(format!("invalid file name: {e}")))
}

fn read_marker(dir: &TrustedDir, marker: &FileName) -> Result<Option<Header>> {
    let raw = match dir.read_limited(marker, HEADER_LEN as u64) {
        Ok(bytes) => bytes,
        Err(cite_core::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(e) => return Err(internal(format!("cannot read {marker}: {e}"))),
    };
    let raw: [u8; HEADER_LEN] = raw
        .try_into()
        .map_err(|_| internal(format!("{marker} is not a complete header")))?;
    Header::decode(&raw).map(Some)
}

// Puts a staged header into the file, flushes it and drops the marker; safe to repeat.
fn apply_marker(
    dir: &TrustedDir,
    name: &FileName,
    marker: &FileName,
    header: &Header,
) -> Result<()> {
    let handle = dir
        .lock_file(name, 0o600)
        .map_err(|e| internal(format!("cannot open {name} for writing: {e}")))?;
    handle
        .write_all_at(&header.encode(), 0)
        .map_err(|e| internal(format!("cannot rewrite the header of {name}: {e}")))?;
    handle
        .sync_all()
        .map_err(|e| internal(format!("cannot flush {name}: {e}")))?;
    dir.unlink(marker)
        .map_err(|e| internal(format!("cannot remove {marker}: {e}")))?;
    dir.sync().ok();
    Ok(())
}

// Writes the header the file should have under the primary key to a marker file, durably; nothing in the stream changes yet.
fn stage_rewrap(
    dir: &TrustedDir,
    name: &FileName,
    marker: &FileName,
    keyring: &Keyring,
    backup_id: &str,
) -> Result<Option<Header>> {
    let (file, _) = dir
        .open_regular(name)
        .map_err(|e| internal(format!("cannot open {name}: {e}")))?;
    let mut raw = [0u8; HEADER_LEN];
    file.read_exact_at(&mut raw, 0)
        .map_err(|_| internal("not a valid backup file: it is shorter than its header"))?;
    let current = Header::decode(&raw)?;
    if current.kid == keyring.kid() {
        return Ok(None);
    }
    let dek = keyring.unwrap_dek(backup_id, current.kid, current.dek_nonce, &current.wrapped)?;
    let (kid, dek_nonce, wrapped) = keyring.wrap_dek(backup_id, &dek)?;
    let next = Header {
        kid,
        dek_nonce,
        wrapped,
        ..current
    };
    write_atomic_in(dir, marker, &next.encode(), 0o600)
        .map_err(|e| internal(format!("cannot stage the new header of {name}: {e}")))?;
    Ok(Some(next))
}

/// Moves a stream's wrapped data key to the primary key. Only the header changes: the new header is
/// written to `<file>.hdr.new` and flushed, then written over the old one in place and flushed, then the
/// marker is removed. A crash leaves the marker, and the next call (or `StreamReader::open`) uses it.
pub fn rewrap_header(path: &Path, keyring: &Keyring, backup_id: &str) -> Result<()> {
    let (dir, name) = TrustedDir::split(path).map_err(core)?;
    let marker = marker_name(&name)?;
    if let Some(staged) = read_marker(&dir, &marker)? {
        return apply_marker(&dir, &name, &marker, &staged);
    }
    match stage_rewrap(&dir, &name, &marker, keyring, backup_id)? {
        Some(staged) => apply_marker(&dir, &name, &marker, &staged),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::{KeySource, NodeKey, OpenMode};
    use proptest::prelude::*;
    use std::os::unix::fs::PermissionsExt;

    const ID: &str = "01HZZZZZZZZZZZZZZZZZZZZZZZ";

    fn key(seed: u8) -> NodeKey {
        NodeKey::from_bytes(&[seed; 32])
    }

    fn ring(seed: u8) -> Keyring {
        Keyring::from_keys(key(seed), KeySource::Env, Vec::new(), OpenMode::Migrating)
    }

    // A deterministic, non-repeating byte pattern, so a reordered or shifted chunk cannot look right.
    fn pattern(len: usize) -> Vec<u8> {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    fn sha(bytes: &[u8]) -> String {
        hex(&Sha256::digest(bytes))
    }

    fn write_stream(path: &Path, ring: &Keyring, data: &[u8], piece: usize) -> StreamSummary {
        let mut writer = StreamWriter::create(path, ring, ID).expect("create");
        for part in data.chunks(piece.max(1)) {
            writer.write_all(part).expect("write");
        }
        writer.finish().expect("finish")
    }

    fn read_all(path: &Path, ring: &Keyring) -> Result<Vec<u8>> {
        let mut reader = StreamReader::open(path, ring, ID)?;
        let mut out = Vec::new();
        reader.read_range(0, u64::MAX, &mut out)?;
        Ok(out)
    }

    #[test]
    fn streams_round_trip_at_the_chunk_boundaries_and_at_ten_mebibytes() {
        let ring = ring(1);
        for size in [0usize, 1, 65_535, 65_536, 65_537, 131_072, 10 * 1024 * 1024] {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("a.cbk");
            let data = pattern(size);
            let summary = write_stream(&path, &ring, &data, 100_003);
            assert_eq!(summary.plaintext_len, size as u64, "{size}");
            assert_eq!(summary.sha256, sha(&data), "{size}");
            assert_eq!(
                summary.stored_len,
                std::fs::metadata(&path).expect("meta").len()
            );
            assert_eq!(summary.stored_len, stored_len(size as u64));
            assert_eq!(read_all(&path, &ring).expect("read"), data, "{size}");
            let mut reader = StreamReader::open(&path, &ring, ID).expect("open");
            let mut sink = Vec::new();
            assert_eq!(
                reader.copy_to(&mut sink).expect("copy"),
                sha(&data),
                "{size}"
            );
            assert_eq!(sink, data, "{size}");
            assert_eq!(reader.plaintext_len(), size as u64);
        }
    }

    #[test]
    fn the_file_is_private_holds_no_plaintext_and_leads_with_the_magic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("a.cbk");
        let marker = b"PLAINTEXT-MARKER-0123456789";
        let mut data = pattern(1000);
        data[100..100 + marker.len()].copy_from_slice(marker);
        write_stream(&path, &ring(1), &data, 7);
        let raw = std::fs::read(&path).expect("read");
        assert_eq!(&raw[..8], MAGIC);
        assert!(!raw.windows(marker.len()).any(|w| w == marker));
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(
            StreamWriter::create(&path, &ring(1), ID).is_err(),
            "never overwrites"
        );
    }

    #[test]
    fn random_access_reads_any_range_without_the_chunks_before_it() {
        let ring = ring(1);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("a.cbk");
        let data = pattern(3 * CHUNK_SIZE + 123);
        write_stream(&path, &ring, &data, 50_000);
        let mut reader = StreamReader::open(&path, &ring, ID).expect("open");
        let total = data.len() as u64;
        for (offset, len) in [
            (0u64, 1u64),
            (CHUNK_SIZE as u64 - 1, 2),
            (CHUNK_SIZE as u64, CHUNK_SIZE as u64),
            (70_000, 130_000),
            (total - 5, 100),
            (total, 10),
            (5, 0),
        ] {
            let mut out = Vec::new();
            reader.read_range(offset, len, &mut out).expect("range");
            let end = (offset + len).min(total);
            assert_eq!(out, data[offset as usize..end as usize], "{offset}+{len}");
        }
        let mut out = Vec::new();
        assert!(reader.read_range(total + 1, 1, &mut out).is_err());
        let mut prefix = vec![9u8];
        reader.read_range(10, 3, &mut prefix).expect("appends");
        assert_eq!(prefix[1..], data[10..13]);

        // damage to the first chunk does not stop a read that never touches it
        let mut raw = std::fs::read(&path).expect("read");
        raw[HEADER_LEN + 5] ^= 0xff;
        std::fs::write(&path, raw).expect("write");
        let mut reader = StreamReader::open(&path, &ring, ID).expect("open");
        let mut tail = Vec::new();
        reader
            .read_range(2 * CHUNK_SIZE as u64, 50, &mut tail)
            .expect("untouched chunk");
        assert_eq!(tail, data[2 * CHUNK_SIZE..2 * CHUNK_SIZE + 50]);
        assert!(reader.read_range(0, 10, &mut Vec::new()).is_err());
    }

    #[test]
    fn a_truncated_stream_is_refused_even_when_the_header_is_patched_to_match() {
        let ring = ring(1);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("a.cbk");
        let data = pattern(2 * CHUNK_SIZE + 10);
        write_stream(&path, &ring, &data, 4096);

        let cut = dir.path().join("cut.cbk");
        std::fs::copy(&path, &cut).expect("copy");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&cut)
            .expect("open");
        file.set_len(std::fs::metadata(&cut).expect("meta").len() - 1)
            .expect("truncate");
        let err = read_all(&cut, &ring).expect_err("truncated").to_string();
        assert!(err.contains("truncated"), "{err}");

        // drop the whole last chunk and rewrite the length: the previous chunk was not sealed as the last
        let patched = dir.path().join("patched.cbk");
        std::fs::copy(&path, &patched).expect("copy");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&patched)
            .expect("open");
        file.set_len(stored_len(2 * CHUNK_SIZE as u64))
            .expect("truncate");
        file.write_all_at(&(2 * CHUNK_SIZE as u64).to_be_bytes(), 92)
            .expect("patch");
        let err = read_all(&patched, &ring)
            .expect_err("flag mismatch")
            .to_string();
        assert!(err.contains("authentication"), "{err}");

        // appended bytes are refused too
        let longer = dir.path().join("longer.cbk");
        std::fs::copy(&path, &longer).expect("copy");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&longer)
            .expect("open");
        file.set_len(std::fs::metadata(&longer).expect("meta").len() + 1)
            .expect("extend");
        assert!(StreamReader::open(&longer, &ring, ID).is_err());
    }

    #[test]
    fn reordered_or_altered_chunks_and_a_wrong_backup_id_are_refused() {
        let ring = ring(1);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("a.cbk");
        let data = pattern(3 * CHUNK_SIZE);
        write_stream(&path, &ring, &data, 65_536);
        let original = std::fs::read(&path).expect("read");
        let body = |i: u64| {
            let start = encrypted_chunk_offset(i) as usize;
            start..start + ENC_CHUNK as usize
        };

        let mut swapped = original.clone();
        swapped[body(0)].copy_from_slice(&original[body(1)]);
        swapped[body(1)].copy_from_slice(&original[body(0)]);
        std::fs::write(&path, &swapped).expect("write");
        assert!(read_all(&path, &ring).is_err(), "reordered chunks");

        let mut flipped = original.clone();
        flipped[body(1)][100] ^= 1;
        std::fs::write(&path, &flipped).expect("write");
        assert!(read_all(&path, &ring).is_err(), "flipped body bit");

        let mut tag = original.clone();
        let last = body(2).end - 1;
        tag[last] ^= 1;
        std::fs::write(&path, &tag).expect("write");
        assert!(read_all(&path, &ring).is_err(), "flipped tag bit");

        let mut header = original.clone();
        header[50] ^= 1;
        std::fs::write(&path, &header).expect("write");
        assert!(
            StreamReader::open(&path, &ring, ID).is_err(),
            "flipped wrapped key bit"
        );

        std::fs::write(&path, &original).expect("restore");
        assert_eq!(read_all(&path, &ring).expect("intact"), data);
        assert!(
            StreamReader::open(&path, &ring, "01HOTHER").is_err(),
            "wrong backup id"
        );
        assert!(
            StreamReader::open(&path, &self::ring(2), ID).is_err(),
            "wrong key"
        );

        let mut magic = original.clone();
        magic[0] = b'X';
        std::fs::write(&path, &magic).expect("write");
        assert!(StreamReader::open(&path, &ring, ID).is_err(), "wrong magic");
        let short = dir.path().join("short.cbk");
        std::fs::write(&short, &original[..60]).expect("write");
        assert!(StreamReader::open(&short, &ring, ID).is_err());
    }

    #[test]
    fn chunks_written_out_of_order_and_twice_equal_a_sequential_write() {
        let ring = ring(1);
        let dir = tempfile::tempdir().expect("tempdir");
        let data = pattern(4 * CHUNK_SIZE + 777);
        let sequential = dir.path().join("seq.cbk");
        let expected = write_stream(&sequential, &ring, &data, 12_345);

        let random = dir.path().join("rnd.cbk");
        let mut writer = StreamWriter::create(&random, &ring, ID).expect("create");
        let pieces: Vec<&[u8]> = data.chunks(CHUNK_SIZE).collect();
        for index in [3usize, 0, 4, 2, 1, 2] {
            writer
                .write_chunk_at(index as u64, pieces[index], index == pieces.len() - 1)
                .expect("chunk");
        }
        assert!(writer.write_all(b"x").is_err(), "modes do not mix");
        let summary = writer.finish().expect("finish");
        assert_eq!(summary.plaintext_len, expected.plaintext_len);
        assert_eq!(summary.sha256, expected.sha256);
        assert_eq!(summary.stored_len, expected.stored_len);
        assert_eq!(read_all(&random, &ring).expect("read"), data);
    }

    #[test]
    fn out_of_order_imports_refuse_gaps_a_missing_last_and_malformed_chunks() {
        let ring = ring(1);
        let dir = tempfile::tempdir().expect("tempdir");
        let data = pattern(2 * CHUNK_SIZE + 5);
        let pieces: Vec<&[u8]> = data.chunks(CHUNK_SIZE).collect();
        let fresh =
            |name: &str| StreamWriter::create(&dir.path().join(name), &ring, ID).expect("create");

        let mut gap = fresh("gap.cbk");
        gap.write_chunk_at(0, pieces[0], false).expect("chunk");
        gap.write_chunk_at(2, pieces[2], true).expect("chunk");
        assert!(matches!(gap.finish(), Err(ConnectorError::Conflict(_))));

        let mut no_last = fresh("nolast.cbk");
        no_last.write_chunk_at(0, pieces[0], false).expect("chunk");
        no_last.write_chunk_at(1, pieces[1], false).expect("chunk");
        assert!(matches!(no_last.finish(), Err(ConnectorError::Conflict(_))));

        let mut bad = fresh("bad.cbk");
        assert!(
            bad.write_chunk_at(0, &pieces[0][..10], false).is_err(),
            "short non-last"
        );
        assert!(
            bad.write_chunk_at(0, &vec![0u8; CHUNK_SIZE + 1], true)
                .is_err(),
            "oversized"
        );
        assert!(
            bad.write_chunk_at(3, &[], true).is_err(),
            "empty last after data"
        );
        bad.write_chunk_at(2, pieces[2], true).expect("last");
        assert!(
            bad.write_chunk_at(5, pieces[0], false).is_err(),
            "chunk past the last"
        );
        assert!(
            bad.write_chunk_at(1, pieces[2], true).is_err(),
            "second last"
        );

        let mut empty = fresh("empty.cbk");
        empty.write_chunk_at(0, &[], true).expect("empty stream");
        let summary = empty.finish().expect("finish");
        assert_eq!(summary.plaintext_len, 0);
        assert_eq!(summary.sha256, sha(b""));
        assert_eq!(
            read_all(&dir.path().join("empty.cbk"), &ring).expect("read"),
            b""
        );
    }

    #[test]
    fn rewrapping_moves_the_data_key_to_the_new_key_and_leaves_the_body_alone() {
        let old = ring(1);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("a.cbk");
        let data = pattern(CHUNK_SIZE + 9);
        write_stream(&path, &old, &data, 9999);
        let before = std::fs::read(&path).expect("read");

        let rotated = Keyring::from_keys(key(2), KeySource::Env, vec![key(1)], OpenMode::Migrating);
        rewrap_header(&path, &rotated, ID).expect("rewrap");
        let after = std::fs::read(&path).expect("read");
        assert_eq!(
            &before[HEADER_LEN..],
            &after[HEADER_LEN..],
            "chunks are untouched"
        );
        assert_ne!(&before[..HEADER_LEN], &after[..HEADER_LEN]);
        assert!(!dir.path().join("a.cbk.hdr.new").exists());

        let only_new = Keyring::from_keys(key(2), KeySource::Env, Vec::new(), OpenMode::Migrating);
        assert_eq!(read_all(&path, &only_new).expect("read"), data);
        assert!(
            read_all(&path, &old).is_err(),
            "the old key no longer opens it"
        );
        let again = std::fs::read(&path).expect("read");
        rewrap_header(&path, &rotated, ID).expect("idempotent");
        assert_eq!(std::fs::read(&path).expect("read"), again);
        assert!(
            rewrap_header(&path, &rotated, "01HOTHER").is_ok(),
            "already on the primary key"
        );

        let wrong = dir.path().join("b.cbk");
        write_stream(&wrong, &old, &data, 9999);
        assert!(
            rewrap_header(&wrong, &rotated, "01HOTHER").is_err(),
            "wrong backup id"
        );
        assert!(rewrap_header(&wrong, &ring(3), ID).is_err(), "unknown key");
    }

    #[test]
    fn an_interrupted_rewrap_is_finished_from_the_marker_and_readers_use_it_meanwhile() {
        let old = ring(1);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("a.cbk");
        let data = pattern(2 * CHUNK_SIZE);
        write_stream(&path, &old, &data, 4096);
        let rotated = Keyring::from_keys(key(2), KeySource::Env, vec![key(1)], OpenMode::Migrating);

        // crash after the marker is durable and before the header is rewritten
        let handle = TrustedDir::open(dir.path()).expect("dir");
        let name = FileName::new("a.cbk").expect("name");
        let marker = marker_name(&name).expect("marker");
        stage_rewrap(&handle, &name, &marker, &rotated, ID)
            .expect("stage")
            .expect("staged");
        assert!(dir.path().join("a.cbk.hdr.new").exists());
        let only_new = Keyring::from_keys(key(2), KeySource::Env, Vec::new(), OpenMode::Migrating);
        assert_eq!(read_all(&path, &only_new).expect("via marker"), data);
        assert!(
            read_all(&path, &old).is_err(),
            "the staged header wins over the file's"
        );

        // crash in the middle of overwriting the header: the file head is torn
        let torn = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open");
        torn.write_all_at(&[0xAA; 40], 0).expect("tear");
        assert!(
            Header::decode(&{
                let mut raw = [0u8; HEADER_LEN];
                std::fs::File::open(&path)
                    .expect("open")
                    .read_exact_at(&mut raw, 0)
                    .expect("read");
                raw
            })
            .is_err()
        );
        assert_eq!(
            read_all(&path, &only_new).expect("marker still serves reads"),
            data
        );

        rewrap_header(&path, &rotated, ID).expect("finish");
        assert!(!dir.path().join("a.cbk.hdr.new").exists());
        assert_eq!(read_all(&path, &only_new).expect("repaired"), data);

        // crash after the header was rewritten and before the marker was removed
        let again = dir.path().join("b.cbk");
        write_stream(&again, &old, &data, 4096);
        let name_b = FileName::new("b.cbk").expect("name");
        let marker_b = marker_name(&name_b).expect("marker");
        let staged = stage_rewrap(&handle, &name_b, &marker_b, &rotated, ID)
            .expect("stage")
            .expect("staged");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&again)
            .expect("open");
        file.write_all_at(&staged.encode(), 0)
            .expect("write header");
        rewrap_header(&again, &rotated, ID).expect("re-applying is harmless");
        assert!(!dir.path().join("b.cbk.hdr.new").exists());
        assert_eq!(read_all(&again, &only_new).expect("read"), data);

        // a marker that is not a whole header is refused rather than applied
        let c = dir.path().join("c.cbk");
        write_stream(&c, &old, &data, 4096);
        std::fs::write(dir.path().join("c.cbk.hdr.new"), b"short").expect("write");
        assert!(rewrap_header(&c, &rotated, ID).is_err());
        assert!(
            read_all(&c, &old).is_err(),
            "a bad marker is not silently ignored"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        #[test]
        fn any_data_written_in_any_pieces_reads_back_whole_and_by_range(
            data in proptest::collection::vec(any::<u8>(), 0..200_000),
            piece in 1usize..90_000,
            a in 0usize..200_000,
            b in 0usize..200_000,
        ) {
            let ring = ring(1);
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("p.cbk");
            let summary = write_stream(&path, &ring, &data, piece);
            prop_assert_eq!(summary.plaintext_len, data.len() as u64);
            prop_assert_eq!(&summary.sha256, &sha(&data));
            prop_assert_eq!(read_all(&path, &ring).unwrap(), data.clone());
            let (from, to) = (a.min(b).min(data.len()), a.max(b).min(data.len()));
            let mut out = Vec::new();
            let mut reader = StreamReader::open(&path, &ring, ID).unwrap();
            reader.read_range(from as u64, (to - from) as u64, &mut out).unwrap();
            prop_assert_eq!(out, data[from..to].to_vec());
        }
    }
}
