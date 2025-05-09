use std::fmt::Debug;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};

#[derive(Debug)]
pub struct ServerError<R: IntoResponse>(pub(crate) cja::color_eyre::Report, pub(crate) R);

pub type ServerResult<S, F = Response> = Result<S, ServerError<F>>;

impl<R: IntoResponse> IntoResponse for ServerError<R> {
    fn into_response(self) -> axum::response::Response {
        tracing::error!(error = ?self.0, "Request Error");

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
