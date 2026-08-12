// Copyright 2026 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Binding a gRPC request to the organization its caller authenticated for.
//!
//! SECURITY (GHSA-5x2v-jg9q-g8qc): a handler must not trust an `org_id` taken
//! from the request body. The auth interceptor checks membership only against
//! the organization *header*, so a user credential for org A can carry a body
//! naming org B and read another tenant's data.

use tonic::{Request, Status};

/// The organization this caller authenticated for, or `None` if the caller is
/// not a user.
///
/// The auth interceptor appends `user_id` metadata only for user-credential
/// callers — internal-token callers (intra-cluster and super-cluster RPCs)
/// leave it absent, and those legitimately address any org. A `Some` must
/// replace whatever the body said; see [`bind_org`].
pub fn authenticated_org<T>(request: &Request<T>) -> Result<Option<String>, Status> {
    let cfg = config::get_config();
    authenticated_org_with(request, &cfg.grpc.org_header_key)
}

/// [`authenticated_org`] with the header key supplied, so the rule itself can
/// be tested without a loaded config.
fn authenticated_org_with<T>(
    request: &Request<T>,
    org_header_key: &str,
) -> Result<Option<String>, Status> {
    let metadata = request.metadata();
    if metadata.get("user_id").is_none() {
        return Ok(None);
    }
    metadata
        .get(org_header_key)
        .and_then(|v| v.to_str().ok())
        .map(|org| Some(org.to_string()))
        .ok_or_else(|| {
            Status::unauthenticated("missing organization header for user-authenticated request")
        })
}

/// Overwrite `org_id` with the caller's authenticated org, for user callers.
///
/// Take this before `into_inner()` consumes the metadata:
///
/// ```ignore
/// let org = authenticated_org(&request)?;
/// let mut req = request.into_inner();
/// bind_org(&mut req.org_id, org);
/// ```
pub fn bind_org(org_id: &mut String, authenticated: Option<String>) {
    if let Some(org) = authenticated {
        *org_id = org;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_with(metadata: &[(&'static str, &str)]) -> Request<()> {
        let mut request = Request::new(());
        for (key, value) in metadata {
            request
                .metadata_mut()
                .insert(*key, value.parse().expect("valid metadata value"));
        }
        request
    }

    /// No `user_id` means an internal-token caller, which may address any org.
    #[test]
    fn internal_callers_are_not_rebound() {
        let request = request_with(&[("organization", "other")]);
        assert_eq!(
            authenticated_org_with(&request, "organization").unwrap(),
            None
        );

        let mut org = "other".to_string();
        bind_org(&mut org, None);
        assert_eq!(org, "other");
    }

    /// A user caller is pinned to the header org, whatever the body claimed.
    #[test]
    fn user_callers_are_rebound_to_their_header_org() {
        let request = request_with(&[("user_id", "viewer@example.com"), ("organization", "mine")]);
        let authenticated = authenticated_org_with(&request, "organization").unwrap();
        assert_eq!(authenticated.as_deref(), Some("mine"));

        let mut org = "victim".to_string();
        bind_org(&mut org, authenticated);
        assert_eq!(org, "mine");
    }

    /// Fail closed: a user caller without an org header is refused rather than
    /// left on the body's value.
    #[test]
    fn a_user_caller_without_an_org_header_is_refused() {
        let request = request_with(&[("user_id", "viewer@example.com")]);
        let err = authenticated_org_with(&request, "organization").unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }
}
