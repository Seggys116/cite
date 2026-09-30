#![forbid(unsafe_code)]

use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use cap_std::ambient_authority;
use cap_std::fs::Dir;
use cite_core::{ContainedOpen, Error, open_contained, request_path};
use flate2::Compression;
use flate2::write::GzEncoder;
use futures_util::stream;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, header};
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use std::sync::LazyLock;
use tokio::sync::Semaphore;

use time::OffsetDateTime;
use time::format_description;

use crate::error_page::{self, BoxBody, apply_security_headers, full_body, page_404};

const STREAM_CHUNK: u64 = 64 * 1024;
const GZIP_MAX_BYTES: u64 = 8 * 1024 * 1024;
const GZIP_CONCURRENCY: usize = 4;

static GZIP_JOBS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(GZIP_CONCURRENCY)));

enum Payload {
    Memory(Vec<u8>),
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
        if let Ok(permit) = GZIP_JOBS.clone().try_acquire_owned() {
            let compressed = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                gzip_file(file, len)
            })
            .await;
            let body = compressed.map_err(|err| Error::msg(err.to_string()))??;
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
    let frames = stream::unfold((Some(file), len), |(file, remaining)| async move {
        if remaining == 0 {
            return None;
        }
        let mut file = file?;
        let want = usize::try_from(remaining.min(STREAM_CHUNK)).unwrap_or(0);
        let read = tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; want];
            let result = file.read(&mut buf).map(|n| {
                buf.truncate(n);
                buf
            });
            (file, result)
        })
        .await;
        let failure = |message: &str| {
            let err: Box<dyn std::error::Error + Send + Sync> =
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, message.to_string()).into();
            Some((Err(err), (None, 0)))
        };
        match read {
            Ok((file, Ok(buf))) if !buf.is_empty() => {
                let left = remaining - buf.len() as u64;
                Some((
                    Ok::<Frame<Bytes>, Box<dyn std::error::Error + Send + Sync>>(Frame::data(
                        Bytes::from(buf),
                    )),
                    (Some(file), left),
                ))
            }
            Ok((_, Ok(_))) => failure("file shrank while being served"),
            Ok((_, Err(err))) => Some((Err(err.into()), (None, 0))),
            Err(_) => failure("file read task failed"),
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
        Payload::Memory(bytes) => (bytes.len() as u64, full_body(Bytes::from(bytes))),
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
