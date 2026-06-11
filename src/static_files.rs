//! Static file server for curf.
//!
//! Serves files from a local directory.
//! Features:
//!   - Path sanitisation — prevents directory traversal (../)
//!   - Index files       — looks for index.html (configurable) in directories
//!   - ETag / If-None-Match caching
//!   - Last-Modified / If-Modified-Since caching
//!   - Accurate MIME types
//!   - Optional directory listing (autoindex)
//!   - HEAD request support

use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Bytes;
use hyper::{header, HeaderMap, Method, Response, StatusCode};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;
use tokio::fs;
use tracing::warn;

pub struct StaticFileServer {
    root: PathBuf,
    index_files: Vec<String>,
    autoindex: bool,
}

impl StaticFileServer {
    pub fn new(root: impl Into<PathBuf>, index_files: Vec<String>, autoindex: bool) -> Self {
        Self {
            root: root.into(),
            index_files,
            autoindex,
        }
    }

    /// Try to serve `path` as a static file.
    /// Returns None when the file does not exist (proxy should fall through to backend).
    pub async fn serve(
        &self,
        url_path: &str,
        method: &Method,
        req_headers: &HeaderMap,
    ) -> Option<Response<BoxBody<Bytes, hyper::Error>>> {
        if *method != Method::GET && *method != Method::HEAD {
            return None;
        }

        let file_path = self.safe_path(url_path)?;

        let meta = fs::metadata(&file_path).await.ok()?;

        if meta.is_dir() {
            // Try each configured index file
            for idx in &self.index_files {
                let candidate = file_path.join(idx);
                if candidate.exists() {
                    return self.serve_file(&candidate, method, req_headers).await;
                }
            }
            // Directory listing
            if self.autoindex {
                return Some(self.directory_listing(&file_path, url_path).await);
            }
            return None;
        }

        self.serve_file(&file_path, method, req_headers).await
    }

    async fn serve_file(
        &self,
        path: &Path,
        method: &Method,
        req_headers: &HeaderMap,
    ) -> Option<Response<BoxBody<Bytes, hyper::Error>>> {
        let meta = fs::metadata(path).await.ok()?;

        // Build ETag from size + mtime
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let etag = format!("\"{}-{}\"", meta.len(), mtime);

        // Check If-None-Match
        if let Some(inm) = req_headers.get(header::IF_NONE_MATCH) {
            if inm.to_str().unwrap_or("") == etag {
                return Some(
                    Response::builder()
                        .status(StatusCode::NOT_MODIFIED)
                        .body(empty_body())
                        .unwrap(),
                );
            }
        }

        // Check If-Modified-Since
        if let Some(ims) = req_headers.get(header::IF_MODIFIED_SINCE) {
            if let Ok(ims_str) = ims.to_str() {
                if let Ok(ims_time) = httpdate::parse_http_date(ims_str) {
                    if let Ok(file_time) = meta.modified() {
                        if file_time <= ims_time {
                            return Some(
                                Response::builder()
                                    .status(StatusCode::NOT_MODIFIED)
                                    .body(empty_body())
                                    .unwrap(),
                            );
                        }
                    }
                }
            }
        }

        let mime = mime_guess::from_path(path)
            .first_or_octet_stream()
            .to_string();

        // For HEAD requests we don't need to read the file
        if *method == Method::HEAD {
            return Some(
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, &mime)
                    .header(header::CONTENT_LENGTH, meta.len())
                    .header(header::ETAG, &etag)
                    .body(empty_body())
                    .unwrap(),
            );
        }

        let data = match fs::read(path).await {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read file {:?}: {}", path, e);
                return None;
            }
        };

        let last_modified = meta
            .modified()
            .ok()
            .map(httpdate::fmt_http_date)
            .unwrap_or_default();

        Some(
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime)
                .header(header::CONTENT_LENGTH, data.len())
                .header(header::ETAG, etag)
                .header(header::LAST_MODIFIED, last_modified)
                .header(header::CACHE_CONTROL, "public, max-age=3600")
                .body(Full::new(Bytes::from(data)).map_err(|e| match e {}).boxed())
                .unwrap(),
        )
    }

    /// Resolve a URL path to a safe filesystem path.
    /// Returns None if the path escapes the root directory.
    fn safe_path(&self, url_path: &str) -> Option<PathBuf> {
        // Decode percent-encoding
        let decoded = percent_encoding::percent_decode_str(url_path)
            .decode_utf8()
            .ok()?;

        // Strip query string if present
        let clean = decoded.split('?').next().unwrap_or(&decoded);

        // Normalise: strip leading slashes, resolve . and ..
        let mut result = self.root.clone();
        for component in Path::new(clean).components() {
            match component {
                Component::Normal(part) => result.push(part),
                Component::ParentDir => {
                    // Never go above root
                    if !result.pop() {
                        return None;
                    }
                }
                Component::RootDir | Component::CurDir => {}
                Component::Prefix(_) => return None, // Windows paths
            }
        }

        // Verify the resolved path is still inside root
        if !result.starts_with(&self.root) {
            warn!("Path traversal attempt blocked: {}", url_path);
            return None;
        }

        Some(result)
    }

    async fn directory_listing(
        &self,
        dir: &Path,
        url_path: &str,
    ) -> Response<BoxBody<Bytes, hyper::Error>> {
        let mut entries = Vec::new();
        if let Ok(mut read_dir) = fs::read_dir(dir).await {
            while let Ok(Some(entry)) = read_dir.next_entry().await {
                let name = entry.file_name().to_string_lossy().into_owned();
                let is_dir = entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false);
                entries.push((name, is_dir));
            }
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let base = url_path.trim_end_matches('/');
        let mut html = format!(
            "<!DOCTYPE html><html><head><title>Index of {}</title>\
            <style>body{{font-family:monospace;padding:1em}}a{{display:block;margin:.2em 0}}</style></head>\
            <body><h1>Index of {}</h1><hr>",
            base, base
        );

        if !base.is_empty() {
            html.push_str("<a href=\"../\">../</a>");
        }
        for (name, is_dir) in &entries {
            let suffix = if *is_dir { "/" } else { "" };
            html.push_str(&format!(
                "<a href=\"{}/{}{}\">{}{}</a>",
                base, name, suffix, name, suffix
            ));
        }
        html.push_str("<hr></body></html>");

        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Full::new(Bytes::from(html)).map_err(|e| match e {}).boxed())
            .unwrap()
    }
}

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new().map_err(|e| match e {}).boxed()
}
