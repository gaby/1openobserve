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

//! What a read-only account (`Viewer`, `SreAgent`) is allowed to do in OSS
//! builds, which have no OpenFGA to enforce roles for them.
//!
//! Three things pass: safe HTTP methods, the query-by-POST routes declared in
//! [`READ_ONLY_ROUTES`], and self-service maintenance of the caller's own
//! account. Everything else, ingestion included, is refused.
//!
//! Paths arrive with the `/api/` and base-uri prefix stripped, so segment 0 is
//! `{org_id}`; a `/v2/` prefix is normalised away like in
//! [`super::ingestion_routes`].

/// The matcher's subject pattern; here the subject is always the caller's email.
use Seg::{Lit, Param, Subject as SelfEmail};
use axum::http::Method;

use super::route_match::{self, Seg};

/// The refusal message, shared by the HTTP and gRPC entry points.
pub const READ_ONLY_DENIED: &str = "Read only account: this operation is not permitted";

/// A route a read-only account may reach despite its write-ish HTTP method.
struct ReadOnlyRoute {
    /// Segment patterns, starting at `{org_id}` (index 0).
    segments: &'static [Seg],
    /// The HTTP method (as `Method::as_str()`) this row applies to.
    method: &'static str,
}

/// Write-method routes a read-only account may still call. Mirrors
/// `src/api/http/src/handler/http/router/mod.rs`; kept in sync by hand. A row
/// belongs here only if it reads with the query in the body, or is self-service
/// maintenance of the caller's own account.
static READ_ONLY_ROUTES: &[ReadOnlyRoute] = &[
    // ---- Search: query travels in the body, nothing is persisted ----
    // `/{org}/_search`
    ReadOnlyRoute {
        segments: &[Param, Lit("_search")],
        method: "POST",
    },
    // `/{org}/_search_partition`
    ReadOnlyRoute {
        segments: &[Param, Lit("_search_partition")],
        method: "POST",
    },
    // `/{org}/_search_stream`
    ReadOnlyRoute {
        segments: &[Param, Lit("_search_stream")],
        method: "POST",
    },
    // `/{org}/_values_stream`
    ReadOnlyRoute {
        segments: &[Param, Lit("_values_stream")],
        method: "POST",
    },
    // `/{org}/_search_multi`
    ReadOnlyRoute {
        segments: &[Param, Lit("_search_multi")],
        method: "POST",
    },
    // `/{org}/_search_multi_stream`
    ReadOnlyRoute {
        segments: &[Param, Lit("_search_multi_stream")],
        method: "POST",
    },
    // `/{org}/_search_partition_multi`
    ReadOnlyRoute {
        segments: &[Param, Lit("_search_partition_multi")],
        method: "POST",
    },
    // `/{org}/_search_history`
    ReadOnlyRoute {
        segments: &[Param, Lit("_search_history")],
        method: "POST",
    },
    // `/{org}/result_schema`
    ReadOnlyRoute {
        segments: &[Param, Lit("result_schema")],
        method: "POST",
    },
    // `/{org}/{stream}/_around`
    ReadOnlyRoute {
        segments: &[Param, Param, Lit("_around")],
        method: "POST",
    },
    // ---- PromQL: POST forms of read endpoints, for long queries ----
    // `/{org}/prometheus/api/v1/{query,query_range,query_exemplars,series,labels,format_query}`
    ReadOnlyRoute {
        segments: &[
            Param,
            Lit("prometheus"),
            Lit("api"),
            Lit("v1"),
            Lit("query"),
        ],
        method: "POST",
    },
    ReadOnlyRoute {
        segments: &[
            Param,
            Lit("prometheus"),
            Lit("api"),
            Lit("v1"),
            Lit("query_range"),
        ],
        method: "POST",
    },
    ReadOnlyRoute {
        segments: &[
            Param,
            Lit("prometheus"),
            Lit("api"),
            Lit("v1"),
            Lit("query_exemplars"),
        ],
        method: "POST",
    },
    ReadOnlyRoute {
        segments: &[
            Param,
            Lit("prometheus"),
            Lit("api"),
            Lit("v1"),
            Lit("series"),
        ],
        method: "POST",
    },
    ReadOnlyRoute {
        segments: &[
            Param,
            Lit("prometheus"),
            Lit("api"),
            Lit("v1"),
            Lit("labels"),
        ],
        method: "POST",
    },
    ReadOnlyRoute {
        segments: &[
            Param,
            Lit("prometheus"),
            Lit("api"),
            Lit("v1"),
            Lit("format_query"),
        ],
        method: "POST",
    },
    // ---- Other reads that take a body ----
    // `/v2/{org}/alerts/{alert_id}/export` — returns what the caller can GET.
    ReadOnlyRoute {
        segments: &[Param, Lit("alerts"), Param, Lit("export")],
        method: "POST",
    },
    // `/{org}/sourcemaps/stacktrace` — symbolicates against stored source maps.
    ReadOnlyRoute {
        segments: &[Param, Lit("sourcemaps"), Lit("stacktrace")],
        method: "POST",
    },
    // ---- Self-service: maintaining one's own account ----
    // `/{org}/users/{own_email}` — own name/password; the users handler
    // separately refuses self role upgrades.
    ReadOnlyRoute {
        segments: &[Param, Lit("users"), SelfEmail],
        method: "PUT",
    },
    // `/{org}/settings/v2/user/{own_email}` — own UI preferences.
    ReadOnlyRoute {
        segments: &[Param, Lit("settings"), Lit("v2"), Lit("user"), SelfEmail],
        method: "POST",
    },
    // `/{org}/settings/v2/user/{own_email}/{key}` — drop one own preference.
    ReadOnlyRoute {
        segments: &[
            Param,
            Lit("settings"),
            Lit("v2"),
            Lit("user"),
            SelfEmail,
            Param,
        ],
        method: "DELETE",
    },
];

/// HTTP methods that cannot mutate state and are therefore always allowed.
fn is_safe_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Does this segment name the caller's own account? Compared case-insensitively
/// and, failing that, percent-decoded — the frontend escapes the `@` on the
/// settings route but not on the users route.
fn is_self_email(segment: &str, user_email: &str) -> bool {
    if segment.is_empty() || user_email.is_empty() {
        return false;
    }
    if segment.eq_ignore_ascii_case(user_email) {
        return true;
    }
    urlencoding::decode(segment).is_ok_and(|decoded| decoded.eq_ignore_ascii_case(user_email))
}

/// May a read-only account perform this request? `path` starts at `{org_id}`;
/// `user_email` is the caller, used only by the self-service rows. A `false`
/// becomes a `403`.
pub fn is_request_allowed(method: &Method, path: &str, user_email: &str) -> bool {
    if is_safe_method(method) {
        return true;
    }

    let path = route_match::strip_api_prefixes(path);
    let method = method.as_str();
    let columns = route_match::columns(path);

    READ_ONLY_ROUTES.iter().any(|route| {
        route.method == method
            && route_match::segments_match(route.segments, &columns, |col| {
                is_self_email(col, user_email)
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "viewer@example.com";

    #[test]
    fn safe_methods_are_always_allowed() {
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(is_request_allowed(&method, "default/dashboards", ME));
            assert!(is_request_allowed(&method, "default/users", ME));
            assert!(is_request_allowed(&method, "anything/at/all", ME));
        }
    }

    #[test]
    fn search_posts_are_allowed() {
        for path in [
            "default/_search",
            "default/_search_partition",
            "default/_search_stream",
            "default/_values_stream",
            "default/_search_multi",
            "default/_search_multi_stream",
            "default/_search_partition_multi",
            "default/_search_history",
            "default/result_schema",
            "default/mystream/_around",
            "default/prometheus/api/v1/query",
            "default/prometheus/api/v1/query_range",
            "default/prometheus/api/v1/query_exemplars",
            "default/prometheus/api/v1/series",
            "default/prometheus/api/v1/labels",
            "default/prometheus/api/v1/format_query",
            "default/alerts/2Abc/export",
            "default/sourcemaps/stacktrace",
        ] {
            assert!(
                is_request_allowed(&Method::POST, path, ME),
                "expected POST /{path} to be allowed"
            );
        }
    }

    #[test]
    fn mutations_are_refused() {
        for (method, path) in [
            (Method::POST, "default/dashboards"),
            (Method::PUT, "default/dashboards/abc"),
            (Method::DELETE, "default/dashboards/abc"),
            (Method::PATCH, "default/dashboards/move"),
            (Method::POST, "default/users"),
            (Method::DELETE, "default/users/someone@example.com"),
            (Method::POST, "default/functions"),
            (Method::POST, "default/streams/mystream"),
            (Method::PUT, "default/streams/mystream/settings"),
            (Method::POST, "default/alerts/templates"),
            (Method::POST, "default/alerts/destinations/test"),
            (Method::POST, "default/functions/test"),
            (Method::POST, "default/alerts/templates/preview"),
            (Method::POST, "default/short"),
            (Method::POST, "default/mcp"),
            (Method::POST, "default/settings"),
            (Method::PUT, "default/passcode"),
            (Method::POST, "default/rumtoken"),
            (Method::POST, "default/service_accounts"),
            (Method::POST, "default/_bulk"),
            (Method::POST, "default/mystream/_json"),
            (Method::POST, "default/v1/logs"),
            (Method::POST, "default/prometheus/api/v1/write"),
        ] {
            assert!(
                !is_request_allowed(&method, path, ME),
                "expected {method} /{path} to be refused"
            );
        }
    }

    #[test]
    fn self_service_is_allowed_only_for_self() {
        assert!(is_request_allowed(
            &Method::PUT,
            &format!("default/users/{ME}"),
            ME
        ));
        assert!(is_request_allowed(
            &Method::PUT,
            "default/users/Viewer@Example.com",
            ME
        ));
        assert!(!is_request_allowed(
            &Method::PUT,
            "default/users/someone.else@example.com",
            ME
        ));

        assert!(is_request_allowed(
            &Method::POST,
            &format!("default/settings/v2/user/{ME}"),
            ME
        ));
        assert!(is_request_allowed(
            &Method::DELETE,
            &format!("default/settings/v2/user/{ME}/theme"),
            ME
        ));
        assert!(!is_request_allowed(
            &Method::POST,
            "default/settings/v2/user/someone.else@example.com",
            ME
        ));
        // The frontend percent-encodes the email on this route.
        assert!(is_request_allowed(
            &Method::POST,
            "default/settings/v2/user/viewer%40example.com",
            ME
        ));
        assert!(is_request_allowed(
            &Method::PUT,
            "default/users/viewer%40example.com",
            ME
        ));
        assert!(!is_request_allowed(
            &Method::POST,
            "default/settings/v2/user/someone.else%40example.com",
            ME
        ));

        assert!(!is_request_allowed(
            &Method::POST,
            "default/settings/v2",
            ME
        ));
        assert!(!is_request_allowed(
            &Method::DELETE,
            "default/settings/v2/theme",
            ME
        ));
    }

    #[test]
    fn v2_prefix_is_normalised() {
        assert!(is_request_allowed(
            &Method::POST,
            "v2/default/alerts/2Abc/export",
            ME
        ));
        assert!(is_request_allowed(&Method::POST, "v2/default/_search", ME));
        assert!(!is_request_allowed(&Method::POST, "v2/default/alerts", ME));
    }

    #[test]
    fn leading_slash_and_trailing_slash_are_tolerated() {
        assert!(is_request_allowed(&Method::POST, "/default/_search", ME));
        assert!(is_request_allowed(&Method::POST, "default/_search/", ME));
        assert!(!is_request_allowed(
            &Method::POST,
            "/default/dashboards",
            ME
        ));
    }

    #[test]
    fn a_stream_named_like_an_allowed_route_does_not_widen_access() {
        // Positional: a stream named `_search` lands in a `Param` slot.
        assert!(!is_request_allowed(
            &Method::POST,
            "default/_search/_json",
            ME
        ));
        assert!(!is_request_allowed(
            &Method::POST,
            "default/users/_search",
            ME
        ));
    }
}
