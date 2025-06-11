use std::fmt::Debug;

use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};

#[derive(Debug)]
pub struct ServerError<R: IntoResponse>(pub(crate) cja::color_eyre::Report, pub(crate) R);

pub type ServerResult<S, F = Response> = Result<S, ServerError<F>>;

impl<R: IntoResponse> IntoResponse for ServerError<R> {
    fn into_response(self) -> axum::response::Response {
        tracing::error!(error = ?self.0, "Request Error");

        // Check if we're in development mode and this is a 500 error
        let is_dev_mode = std::env::var("DEVELOPMENT_MODE")
            .map(|v| v == "1")
            .unwrap_or(false);

        if is_dev_mode {
            // Check if the response would be a 500 error
            let temp_response = self.1.into_response();
            if temp_response.status() == StatusCode::INTERNAL_SERVER_ERROR {
                // Simple HTML escaping - replace dangerous characters
                let error_text = format!("{:?}", self.0)
                    .replace('&', "&amp;")
                    .replace('<', "&lt;")
                    .replace('>', "&gt;")
                    .replace('"', "&quot;")
                    .replace('\'', "&#39;");

                let error_html = format!(
                    r#"<!DOCTYPE html>
<html>
<head>
    <title>Development Error - 500</title>
    <style>
        body {{ font-family: monospace; margin: 20px; background: #1a1a1a; color: #fff; }}
        .error-container {{ background: #2d2d2d; padding: 20px; border-radius: 8px; }}
        .error-title {{ color: #ff6b6b; font-size: 24px; margin-bottom: 20px; }}
        .error-details {{ background: #000; padding: 15px; border-radius: 4px; overflow-x: auto; }}
        pre {{ margin: 0; white-space: pre-wrap; word-wrap: break-word; }}
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-title">Development Mode - Internal Server Error</div>
        <div class="error-details">
            <pre>{}</pre>
        </div>
    </div>
</body>
</html>"#,
                    error_text
                );

                return (StatusCode::INTERNAL_SERVER_ERROR, Html(error_html)).into_response();
            }
            return temp_response;
        }

        self.1.into_response()
    }
}

impl<E> From<E> for ServerError<StatusCode>
where
    E: Into<cja::color_eyre::Report>,
{
    fn from(err: E) -> Self {
        ServerError(err.into(), StatusCode::INTERNAL_SERVER_ERROR)
    }
}

pub(crate) trait WithStatus<T> {
    fn with_status(self, status: StatusCode) -> Result<T, ServerError<StatusCode>>;
}

impl<T> WithStatus<T> for Result<T, cja::color_eyre::Report> {
    fn with_status(self, status: StatusCode) -> Result<T, ServerError<StatusCode>> {
        match self {
            Ok(val) => Ok(val),
            Err(err) => Err(ServerError(err, status)),
        }
    }
}

pub(crate) trait WithRedirect<T> {
    fn with_redirect(self, redirect: Redirect) -> Result<T, ServerError<Redirect>>;
}

impl<T> WithRedirect<T> for Result<T, cja::color_eyre::Report> {
    fn with_redirect(self, redirect: Redirect) -> Result<T, ServerError<Redirect>> {
        match self {
            Ok(val) => Ok(val),
            Err(err) => Err(ServerError(err, redirect)),
        }
    }
}
