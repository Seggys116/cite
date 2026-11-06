#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use bytes::{Bytes, BytesMut};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, MetadataExt as _};
use cite_core::{ContainedOpen, Error, open_contained, request_path};
use flate2::Compression;
use flate2::write::GzEncoder;
use futures_util::stream;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, header};
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use std::sync::LazyLock;
use tokio::io::AsyncReadExt as _;
use tokio::sync::Semaphore;

use time::OffsetDateTime;
use time::format_description;

use crate::error_page::{self, BoxBody, apply_security_headers, full_body, page_404};

/// Large reads keep the blocking-pool round trips per file low on a single CPU.
const STREAM_CHUNK: u64 = 512 * 1024;
const GZIP_MAX_BYTES: u64 = 8 * 1024 * 1024;
const GZIP_CONCURRENCY: usize = 4;
const GZIP_CACHE_DEFAULT_BYTES: u64 = 64 * 1024 * 1024;
const GZIP_CACHE_ENV: &str = "CITE_GZIP_CACHE_BYTES";
const CACHE_ASSET: &str = "public, max-age=86400, stale-while-revalidate=604800";
const ASSET_EXTENSIONS: [&str; 26] = [
    "png", "jpg", "jpeg", "gif", "webp", "avif", "ico", "bmp", "svg", "woff", "woff2", "ttf",
    "otf", "eot", "mp4", "webm", "mp3", "ogg", "wav", "m4a", "mov", "mkv", "flac", "aac", "opus",
    "apng",
];

static GZIP_JOBS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(GZIP_CONCURRENCY)));

/// Compressed bodies are kept per file version so repeat requests skip the gzip work.
static GZIP_CACHE: LazyLock<GzipCache> = LazyLock::new(|| {
    let budget = std::env::var(GZIP_CACHE_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(GZIP_CACHE_DEFAULT_BYTES);
    GzipCache::new(budget)
});

#[derive(Clone, PartialEq, Eq, Hash)]
struct GzipKey {
    dev: u64,
    ino: u64,
    rel: PathBuf,
    etag: String,
    encoding: &'static str,
}

#[derive(Default)]
struct GzipInner {
    entries: HashMap<GzipKey, (Bytes, u64)>,
    order: BTreeMap<u64, GzipKey>,
    bytes: u64,
    tick: u64,
}

/// Byte-budgeted LRU: the sum of cached body lengths never exceeds `budget`.
struct GzipCache {
    budget: u64,
    inner: Mutex<GzipInner>,
}

impl GzipCache {
    fn new(budget: u64) -> Self {
        Self {
            budget,
            inner: Mutex::new(GzipInner::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, GzipInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn get(&self, key: &GzipKey) -> Option<Bytes> {
        let mut inner = self.lock();
        let inner = &mut *inner;
        let (body, old_tick) = inner.entries.get_mut(key)?;
        inner.tick += 1;
        inner.order.remove(old_tick);
        inner.order.insert(inner.tick, key.clone());
        *old_tick = inner.tick;
        Some(body.clone())
    }

    fn insert(&self, key: GzipKey, body: Bytes) {
        let size = body.len() as u64;
        if size > self.budget {
            return;
        }
        let mut inner = self.lock();
        if let Some((old, tick)) = inner.entries.remove(&key) {
            inner.bytes -= old.len() as u64;
            inner.order.remove(&tick);
        }
        while inner.bytes + size > self.budget {
            let Some((_, oldest)) = inner.order.pop_first() else {
                break;
            };
            if let Some((evicted, _)) = inner.entries.remove(&oldest) {
                inner.bytes -= evicted.len() as u64;
            }
        }
        inner.tick += 1;
        let tick = inner.tick;
        inner.order.insert(tick, key.clone());
        inner.entries.insert(key, (body, tick));
        inner.bytes += size;
    }
}

enum Payload {
    Memory(Bytes),
    File { file: std::fs::File, len: u64 },
}

static HTTP_DATE: LazyLock<format_description::OwnedFormatItem> = LazyLock::new(|| {
    format_description::parse_owned::<2>(
        "[weekday repr:short], [day padding:zero] [month repr:short] [year] [hour]:[minute]:[second] GMT",
    )
    .expect("http date format")
});

pub async fn serve_static(
    req: &Request<hyper::body::Incoming>,
    app_root: &Path,
    spa_fallback: Option<&str>,
    static_headers: &[(String, String)],
) -> Response<BoxBody> {
    let method = req.method().clone();
    if method == Method::OPTIONS {
        let mut res = Response::new(full_body(Bytes::new()));
        *res.status_mut() = StatusCode::NO_CONTENT;
        res.headers_mut().insert(
            header::ALLOW,
            HeaderValue::from_static("GET, HEAD, OPTIONS"),
        );
        apply_security_headers(res.headers_mut(), static_headers);
        return res;
    }
    if method != Method::GET && method != Method::HEAD {
        return error_page::method_not_allowed();
    }

    let path = req.uri().path();
    let root = match Dir::open_ambient_dir(app_root, ambient_authority()) {
        Ok(d) => d,
        Err(_) => return page_404(),
    };

    match serve_path(&root, path, req, spa_fallback, &method, static_headers).await {
        Ok(res) => res,
        Err(Error::NotFound(_)) => {
            if let Some(fallback) = spa_fallback {
                if wants_spa(req, path) {
                    if let Ok(res) =
                        serve_file_at(&root, fallback, req, &method, static_headers, true).await
                    {
                        return res;
                    }
                }
            }
            if let Ok(res) =
                serve_file_at(&root, "404.html", req, &method, static_headers, false).await
            {
                let (parts, body) = res.into_parts();
                let mut res = Response::from_parts(parts, body);
                *res.status_mut() = StatusCode::NOT_FOUND;
                return res;
            }
            let mut res = page_404();
            apply_security_headers(res.headers_mut(), static_headers);
            res
        }
        Err(Error::PathEscape(_)) => {
            let mut res = page_404();
            apply_security_headers(res.headers_mut(), static_headers);
            res
        }
        Err(_) => {
            let mut res = page_404();
            apply_security_headers(res.headers_mut(), static_headers);
            res
        }
    }
}

async fn serve_path(
    root: &Dir,
    url_path: &str,
    req: &Request<hyper::body::Incoming>,
    spa_fallback: Option<&str>,
    method: &Method,
    static_headers: &[(String, String)],
) -> cite_core::Result<Response<BoxBody>> {
    let _ = spa_fallback;
    let parsed = request_path(url_path)?;
    let open = open_contained(root, url_path)?;

    match open {
        ContainedOpen::Directory { rel } => {
            if !parsed.trailing_slash && !rel.as_os_str().is_empty() {
                let loc = if url_path.ends_with('/') {
                    url_path.to_string()
                } else {
                    format!("{url_path}/")
                };
                let mut res = Response::new(full_body(Bytes::new()));
                *res.status_mut() = StatusCode::MOVED_PERMANENTLY;
                if let Ok(v) = HeaderValue::from_str(&loc) {
                    res.headers_mut().insert(header::LOCATION, v);
                }
                apply_security_headers(res.headers_mut(), static_headers);
                return Ok(res);
            }
            let index_rel = if rel.as_os_str().is_empty() {
                PathBuf::from("index.html")
            } else {
                rel.join("index.html")
            };
            let index_url = format!("/{}", index_rel.to_string_lossy().replace('\\', "/"));
            serve_file_open(root, &index_url, req, method, static_headers, false).await
        }
        ContainedOpen::File { .. } => {
            // If URL has trailing slash but target is a file, 404.
            if parsed.trailing_slash {
                return Err(Error::NotFound(url_path.into()));
            }
            serve_file_open(root, url_path, req, method, static_headers, false).await
        }
    }
}

async fn serve_file_at(
    root: &Dir,
    rel: &str,
    req: &Request<hyper::body::Incoming>,
    method: &Method,
    static_headers: &[(String, String)],
    is_spa: bool,
) -> cite_core::Result<Response<BoxBody>> {
    let url = if rel.starts_with('/') {
        rel.to_string()
    } else {
        format!("/{rel}")
    };
    serve_file_open(root, &url, req, method, static_headers, is_spa).await
}

async fn serve_file_open(
    root: &Dir,
    url_path: &str,
    req: &Request<hyper::body::Incoming>,
    method: &Method,
    static_headers: &[(String, String)],
    force_html_cache: bool,
) -> cite_core::Result<Response<BoxBody>> {
    let ContainedOpen::File { rel, file, len } = open_contained(root, url_path)? else {
        return Err(Error::NotFound(url_path.into()));
    };

    let meta = file.metadata()?;
    let mtime_std = meta.modified().ok().map(|t| t.into_std());
    let etag = make_etag(len, mtime_std);
    let last_mod = mtime_std.and_then(format_http_date);

    if let Some(inm) = req.headers().get(header::IF_NONE_MATCH) {
        if header_list_contains(inm, &etag) {
            let mut res = Response::new(full_body(Bytes::new()));
            *res.status_mut() = StatusCode::NOT_MODIFIED;
            set_common_headers(
                res.headers_mut(),
                &rel,
                &etag,
                last_mod.as_deref(),
                force_html_cache,
                static_headers,
                None,
                None,
            );
            return Ok(res);
        }
    }
    if let (Some(ims), Some(lm)) = (req.headers().get(header::IF_MODIFIED_SINCE), &last_mod) {
        if ims.to_str().ok() == Some(lm.as_str()) {
            let mut res = Response::new(full_body(Bytes::new()));
            *res.status_mut() = StatusCode::NOT_MODIFIED;
            set_common_headers(
                res.headers_mut(),
                &rel,
                &etag,
                last_mod.as_deref(),
                force_html_cache,
                static_headers,
                None,
                None,
            );
            return Ok(res);
        }
    }

    let mime = mime_guess::from_path(&rel)
        .first_or_octet_stream()
        .essence_str()
        .to_string();
    let accept_enc = req
        .headers()
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if let Some((enc, pre_path)) = negotiate_precompressed(root, &rel, accept_enc) {
        if let Ok(ContainedOpen::File {
            file: pre_file,
            len: pre_len,
            ..
        }) = open_contained(root, &pre_path)
        {
            return finish_body(
                method,
                Payload::File {
                    file: pre_file.into_std(),
                    len: pre_len,
                },
                StatusCode::OK,
                &rel,
                &etag,
                last_mod.as_deref(),
                &mime,
                force_html_cache,
                static_headers,
                Some(enc),
                None,
            );
        }
    }

    let mut file = file.into_std();
    if let Some(range) = req
        .headers()
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
    {
        if let Some((start, end)) = parse_single_range(range, len) {
            file.seek(SeekFrom::Start(start))?;
            let content_range = format!("bytes {start}-{end}/{len}");
            return finish_body(
                method,
                Payload::File {
                    file,
                    len: end - start + 1,
                },
                StatusCode::PARTIAL_CONTENT,
                &rel,
                &etag,
                last_mod.as_deref(),
                &mime,
                force_html_cache,
                static_headers,
                None,
                Some(content_range),
            );
        }
    }

    let gzip_wanted = accept_enc.contains("gzip")
        && is_compressible(&mime)
        && len > 256
        && len <= GZIP_MAX_BYTES
        && *method != Method::HEAD;
    if gzip_wanted {
        let key = GzipKey {
            dev: meta.dev(),
            ino: meta.ino(),
            rel: rel.clone(),
            etag: etag.clone(),
            encoding: "gzip",
        };
        let cached = GZIP_CACHE.get(&key);
        let permit = if cached.is_some() {
            None
        } else {
            GZIP_JOBS.clone().try_acquire_owned().ok()
        };
        if cached.is_some() || permit.is_some() {
            let body = match cached {
                Some(body) => body,
                None => {
                    let compressed = tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        gzip_file(file, len)
                    })
                    .await;
                    let body = Bytes::from(compressed.map_err(|err| Error::msg(err.to_string()))??);
                    GZIP_CACHE.insert(key, body.clone());
                    body
                }
            };
            return finish_body(
                method,
                Payload::Memory(body),
                StatusCode::OK,
                &rel,
                &etag,
                last_mod.as_deref(),
                &mime,
                force_html_cache,
                static_headers,
                Some("gzip"),
                None,
            );
        }
    }

    finish_body(
        method,
        Payload::File { file, len },
        StatusCode::OK,
        &rel,
        &etag,
        last_mod.as_deref(),
        &mime,
        force_html_cache,
        static_headers,
        None,
        None,
    )
}

fn gzip_file(mut file: std::fs::File, len: u64) -> cite_core::Result<Vec<u8>> {
    use std::io::Write;
    let mut raw = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    file.read_to_end(&mut raw)?;
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(&raw)?;
    Ok(enc.finish()?)
}

fn file_body(file: std::fs::File, len: u64) -> BoxBody {
    let file = tokio::fs::File::from_std(file);
    let frames = stream::unfold((Some(file), len), |(file, remaining)| async move {
        if remaining == 0 {
            return None;
        }
        let mut file = file?;
        let want = remaining.min(STREAM_CHUNK);
        // Spare capacity is handed to the read as is, so the buffer is never zero-filled.
        let mut buf = BytesMut::with_capacity(usize::try_from(want).unwrap_or(0));
        let read = (&mut file).take(want).read_buf(&mut buf).await;
        match read {
            Ok(n) if n > 0 => Some((
                Ok::<Frame<Bytes>, Box<dyn std::error::Error + Send + Sync>>(Frame::data(
                    buf.freeze(),
                )),
                (Some(file), remaining - n as u64),
            )),
            Ok(_) => {
                let err: Box<dyn std::error::Error + Send + Sync> = std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "file shrank while being served",
                )
                .into();
                Some((Err(err), (None, 0)))
            }
            Err(err) => Some((Err(err.into()), (None, 0))),
        }
    });
    StreamBody::new(frames).boxed_unsync()
}

#[allow(clippy::too_many_arguments)]
fn finish_body(
    method: &Method,
    body: Payload,
    status: StatusCode,
    rel: &Path,
    etag: &str,
    last_mod: Option<&str>,
    mime: &str,
    force_html_cache: bool,
    static_headers: &[(String, String)],
    content_encoding: Option<&'static str>,
    content_range: Option<String>,
) -> cite_core::Result<Response<BoxBody>> {
    let (len, body) = match body {
        Payload::Memory(bytes) => (bytes.len() as u64, full_body(bytes)),
        Payload::File { file, len } => (len, file_body(file, len)),
    };
    let body = if *method == Method::HEAD {
        full_body(Bytes::new())
    } else {
        body
    };
    let mut res = Response::new(body);
    *res.status_mut() = status;
    set_common_headers(
        res.headers_mut(),
        rel,
        etag,
        last_mod,
        force_html_cache || mime.contains("html"),
        static_headers,
        content_encoding,
        content_range.as_deref(),
    );
    if let Ok(v) = HeaderValue::from_str(mime) {
        res.headers_mut().insert(header::CONTENT_TYPE, v);
    }
    if *method != Method::HEAD || status != StatusCode::NOT_MODIFIED {
        res.headers_mut().insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&len.to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("0")),
        );
    }
    res.headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    Ok(res)
}

#[allow(clippy::too_many_arguments)]
fn set_common_headers(
    headers: &mut HeaderMap,
    rel: &Path,
    etag: &str,
    last_mod: Option<&str>,
    htmlish: bool,
    static_headers: &[(String, String)],
    content_encoding: Option<&str>,
    content_range: Option<&str>,
) {
    if let Ok(v) = HeaderValue::from_str(etag) {
        headers.insert(header::ETAG, v);
    }
    if let Some(lm) = last_mod {
        if let Ok(v) = HeaderValue::from_str(lm) {
            headers.insert(header::LAST_MODIFIED, v);
        }
    }
    let cache = if htmlish {
        "no-cache"
    } else if is_fingerprinted(rel) {
        "public, max-age=31536000, immutable"
    } else if is_media_asset(rel) {
        CACHE_ASSET
    } else {
        "public, max-age=3600"
    };
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    if let Some(enc) = content_encoding {
        if let Ok(v) = HeaderValue::from_str(enc) {
            headers.insert(header::CONTENT_ENCODING, v);
        }
        headers.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    }
    if let Some(cr) = content_range {
        if let Ok(v) = HeaderValue::from_str(cr) {
            headers.insert(header::CONTENT_RANGE, v);
        }
    }
    apply_security_headers(headers, static_headers);
}

fn negotiate_precompressed(root: &Dir, rel: &Path, accept: &str) -> Option<(&'static str, String)> {
    let rel_s = rel.to_string_lossy().replace('\\', "/");
    if accept.contains("br") {
        let br = format!("/{rel_s}.br");
        if matches!(open_contained(root, &br), Ok(ContainedOpen::File { .. })) {
            return Some(("br", br));
        }
    }
    if accept.contains("gzip") {
        let gz = format!("/{rel_s}.gz");
        if matches!(open_contained(root, &gz), Ok(ContainedOpen::File { .. })) {
            return Some(("gzip", gz));
        }
    }
    None
}

fn is_fingerprinted(rel: &Path) -> bool {
    let name = rel.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let bytes = name.as_bytes();
    let mut run = 0usize;
    for &b in bytes {
        if b.is_ascii_hexdigit() {
            run += 1;
            if run >= 8 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn is_media_asset(rel: &Path) -> bool {
    rel.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| ASSET_EXTENSIONS.iter().any(|a| ext.eq_ignore_ascii_case(a)))
}

fn is_compressible(mime: &str) -> bool {
    mime.starts_with("text/")
        || mime == "application/javascript"
        || mime == "application/json"
        || mime == "image/svg+xml"
        || mime == "application/xml"
}

fn make_etag(len: u64, mtime: Option<SystemTime>) -> String {
    match mtime.and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok()) {
        Some(d) => format!("\"{len:x}-{:x}\"", d.as_secs()),
        None => format!("\"{len:x}\""),
    }
}

fn format_http_date(t: SystemTime) -> Option<String> {
    let dt = OffsetDateTime::from(t);
    dt.format(&HTTP_DATE).ok()
}

fn header_list_contains(header: &HeaderValue, etag: &str) -> bool {
    let Ok(s) = header.to_str() else {
        return false;
    };
    s.split(',')
        .any(|part| part.trim() == etag || part.trim() == "*")
}

fn parse_single_range(header: &str, len: u64) -> Option<(u64, u64)> {
    let header = header.trim();
    let rest = header.strip_prefix("bytes=")?;
    if rest.contains(',') {
        return None; // multiparts not supported
    }
    let (start_s, end_s) = rest.split_once('-')?;
    if start_s.is_empty() {
        let n: u64 = end_s.parse().ok()?;
        if n == 0 || len == 0 {
            return None;
        }
        let start = len.saturating_sub(n);
        return Some((start, len - 1));
    }
    let start: u64 = start_s.parse().ok()?;
    let end = if end_s.is_empty() {
        len.saturating_sub(1)
    } else {
        end_s.parse().ok()?
    };
    if start > end || start >= len {
        return None;
    }
    Some((start, end.min(len - 1)))
}

fn wants_spa(req: &Request<hyper::body::Incoming>, path: &str) -> bool {
    let last = path.rsplit('/').next().unwrap_or(path);
    if last.contains('.') {
        return false;
    }
    req.headers()
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_none_or(|a| a.contains("text/html") || a.contains("*/*"))
}

pub fn static_health_ok(app_root: &Path, health_path: &str) -> bool {
    let Ok(root) = Dir::open_ambient_dir(app_root, ambient_authority()) else {
        return false;
    };
    matches!(
        open_contained(&root, health_path),
        Ok(ContainedOpen::File { .. }) | Ok(ContainedOpen::Directory { .. })
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn pattern(i: u64) -> u8 {
        (i.wrapping_mul(31) ^ (i >> 8)) as u8
    }

    fn write_pattern(dir: &Path, name: &str, len: u64) -> PathBuf {
        let path = dir.join(name);
        let mut out = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
        let mut chunk = vec![0u8; 1 << 16];
        let mut at = 0u64;
        while at < len {
            let n = (len - at).min(chunk.len() as u64) as usize;
            for (k, b) in chunk[..n].iter_mut().enumerate() {
                *b = pattern(at + k as u64);
            }
            out.write_all(&chunk[..n]).unwrap();
            at += n as u64;
        }
        out.flush().unwrap();
        path
    }

    async fn collect(body: BoxBody) -> (Vec<u8>, usize) {
        let mut body = body;
        let mut out = Vec::new();
        let mut frames = 0;
        while let Some(frame) = body.frame().await {
            let frame = frame.unwrap();
            if let Ok(data) = frame.into_data() {
                frames += 1;
                out.extend_from_slice(&data);
            }
        }
        (out, frames)
    }

    fn open_at(path: &Path, start: u64) -> std::fs::File {
        let mut file = std::fs::File::open(path).unwrap();
        file.seek(SeekFrom::Start(start)).unwrap();
        file
    }

    fn check(bytes: &[u8], start: u64) {
        for (k, b) in bytes.iter().enumerate() {
            assert_eq!(*b, pattern(start + k as u64), "byte {}", start + k as u64);
        }
    }

    #[tokio::test]
    async fn a_20_mib_file_streams_in_a_bounded_number_of_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let len = 20 * 1024 * 1024;
        let path = write_pattern(dir.path(), "big.bin", len);
        let (bytes, frames) = collect(file_body(open_at(&path, 0), len)).await;
        assert_eq!(bytes.len() as u64, len);
        check(&bytes, 0);
        let max_frames = len.div_ceil(STREAM_CHUNK) as usize;
        assert!(
            frames <= max_frames,
            "{frames} frames for {max_frames} chunks"
        );
        assert!(frames >= 2);
    }

    #[tokio::test]
    async fn ranges_across_chunk_boundaries_return_exact_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let len = 3 * STREAM_CHUNK + 777;
        let path = write_pattern(dir.path(), "r.bin", len);
        for (start, end) in [
            (STREAM_CHUNK - 3, STREAM_CHUNK + 2),
            (STREAM_CHUNK, 2 * STREAM_CHUNK - 1),
            (5, 2 * STREAM_CHUNK + 5),
            (2 * STREAM_CHUNK - 1, len - 1),
            (len - 1, len - 1),
            (0, 0),
        ] {
            let want = end - start + 1;
            let (bytes, _) = collect(file_body(open_at(&path, start), want)).await;
            assert_eq!(bytes.len() as u64, want, "{start}-{end}");
            check(&bytes, start);
        }
        assert_eq!(
            parse_single_range("bytes=-10", len),
            Some((len - 10, len - 1))
        );
    }

    #[tokio::test]
    async fn a_file_that_shrinks_mid_stream_fails_instead_of_truncating_silently() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_pattern(dir.path(), "s.bin", 1000);
        let mut body = file_body(open_at(&path, 0), 5000);
        let mut saw_error = false;
        while let Some(frame) = body.frame().await {
            if frame.is_err() {
                saw_error = true;
                break;
            }
        }
        assert!(saw_error);
    }

    fn key(name: &str, etag: &str) -> GzipKey {
        GzipKey {
            dev: 1,
            ino: 2,
            rel: PathBuf::from(name),
            etag: etag.into(),
            encoding: "gzip",
        }
    }

    #[test]
    fn gzip_cache_hits_misses_and_a_changed_etag_misses() {
        let cache = GzipCache::new(1024);
        assert!(cache.get(&key("a.js", "\"1\"")).is_none());
        cache.insert(key("a.js", "\"1\""), Bytes::from_static(b"zipped"));
        assert_eq!(&cache.get(&key("a.js", "\"1\"")).unwrap()[..], b"zipped");
        assert!(cache.get(&key("a.js", "\"2\"")).is_none());
    }

    #[test]
    fn gzip_cache_evicts_least_recently_used_within_the_byte_budget() {
        let cache = GzipCache::new(100);
        let body = |n: usize| Bytes::from(vec![7u8; n]);
        cache.insert(key("a", "e"), body(40));
        cache.insert(key("b", "e"), body(40));
        assert!(cache.get(&key("a", "e")).is_some());
        cache.insert(key("c", "e"), body(40));
        assert!(cache.get(&key("b", "e")).is_none(), "b was least recent");
        assert!(cache.get(&key("a", "e")).is_some());
        assert!(cache.get(&key("c", "e")).is_some());
        assert_eq!(cache.lock().bytes, 80);

        cache.insert(key("huge", "e"), body(101));
        assert!(cache.get(&key("huge", "e")).is_none());
        cache.insert(key("a", "e"), body(10));
        let inner = cache.lock();
        assert_eq!(inner.bytes, 50);
        assert_eq!(inner.entries.len(), inner.order.len());
    }

    #[test]
    fn gzip_cache_never_exceeds_its_budget_and_zero_disables_it() {
        let cache = GzipCache::new(1000);
        for i in 0..200 {
            cache.insert(
                key(&format!("f{i}"), "e"),
                Bytes::from(vec![0u8; 37 + i % 11]),
            );
            assert!(cache.lock().bytes <= 1000);
        }
        let off = GzipCache::new(0);
        off.insert(key("a", "e"), Bytes::from_static(b"x"));
        assert!(off.get(&key("a", "e")).is_none());
    }

    fn cache_control(name: &str, htmlish: bool) -> String {
        let mut headers = HeaderMap::new();
        set_common_headers(
            &mut headers,
            Path::new(name),
            "\"e\"",
            None,
            htmlish,
            &[],
            None,
            None,
        );
        headers[header::CACHE_CONTROL].to_str().unwrap().to_string()
    }

    #[test]
    fn cache_control_depends_on_the_file_type() {
        let asset = "public, max-age=86400, stale-while-revalidate=604800";
        for name in [
            "logo.png",
            "photo.JPG",
            "a/b/hero.webp",
            "font.woff2",
            "icon.svg",
            "clip.mp4",
            "song.mp3",
            "favicon.ico",
        ] {
            assert_eq!(cache_control(name, false), asset, "{name}");
        }
        assert_eq!(cache_control("index.html", true), "no-cache");
        assert_eq!(
            cache_control("chunk-1a2b3c4d5e.js", false),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(
            cache_control("hero-0123abcd.png", false),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(cache_control("app.js", false), "public, max-age=3600");
        assert_eq!(cache_control("data.json", false), "public, max-age=3600");
        assert_eq!(cache_control("noext", false), "public, max-age=3600");
    }
}
