//! Simple error response helpers.

use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Bytes;
use hyper::{header, Response, StatusCode};

/// Build a plain-text error response.
pub fn error_response(status: StatusCode, message: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(
            Full::new(Bytes::from(format!("{} {}\n", status.as_u16(), message)))
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap()
}

/// Build a minimal HTML error page.
pub fn html_error(
    status: StatusCode,
    title: &str,
    body: &str,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head><title>{code} {title}</title>
<style>body{{font-family:sans-serif;text-align:center;padding:4em}}h1{{font-size:3em}}p{{color:#666}}</style>
</head>
<body>
<h1>{code}</h1>
<p>{body}</p>
<hr><small>curf</small>
</body>
</html>"#,
        code = status.as_u16(),
        title = title,
        body = body,
    );

    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Full::new(Bytes::from(html)).map_err(|e| match e {}).boxed())
        .unwrap()
}
