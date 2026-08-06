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

//! What a **read only account** is allowed to do.
//!
//! Enterprise builds answer this question with OpenFGA: every route carries a
//! declared permission and the authorization model decides. OSS builds have no
//! FGA, so `Viewer` (and the system-managed `SreAgent`) would otherwise be
//! indistinguishable from `Admin` once authenticated. This module is the OSS
//! answer — a single, declarative source of truth that the auth layer consults
//! for every authenticated request made by a read-only account.
//!
//! The rule is deliberately narrow, so that "read only" means exactly that:
//!
//! 1. **Safe HTTP methods pass.** `GET`, `HEAD` and `OPTIONS` never mutate.
//! 2. **A short allowlist of query-by-POST routes passes.** Search and PromQL-style endpoints use
//!    `POST` only because the query travels in the request body; they persist nothing. Each row in
//!    [`READ_ONLY_ROUTES`] is an endpoint of that kind and nothing else — no "test", "preview" or
//!    "create" endpoints, however harmless they look.
//! 3. **A read-only account may maintain its own account.** Updating one's own profile/password and
//!    one's own per-user UI settings is self-service, not a privileged write, so it is allowed when
//!    the email in the path is the caller's own.
//!
//! Everything else — every other `POST`/`PUT`/`PATCH`/`DELETE`, including all
//! ingestion — is refused. Adding a new read-only endpoint that uses a write
//! method means adding a row here and nothing else.
//!
//! Paths are matched with the `/api/` (and base-uri) prefix already stripped,
//! so segment 0 is `{org_id}`; an optional `/v2/` prefix is normalised away
//! first, exactly like [`super::ingestion_routes`].

use axum::http::Method;

/// One segment of a declared route pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seg {
    /// A fixed path segment that must match exactly (e.g. `_search`).
    Lit(&'static str),
    /// A single path parameter — matches any one non-empty segment
    /// (`{org_id}`, `{stream_name}`, `{alert_id}`, ...).
    Param,
    /// A single path parameter that must equal the caller's own email. This is
    /// what turns "update a user" into "update *my* user".
    SelfEmail,
}

use Seg::{Lit, Param, SelfEmail};

/// A route a read-only account may reach despite its write-ish HTTP method.
struct ReadOnlyRoute {
    /// Segment patterns, starting at `{org_id}` (index 0).
    segments: &'static [Seg],
    /// HTTP methods (as `Method::as_str()` values) this row applies to.
    methods: &'static [&'static str],
}

/// The authoritative table of write-method routes that a read-only account may
/// still call. Mirrors `src/api/http/src/handler/http/router/mod.rs`; kept in
/// sync by hand.
///
/// Every row must satisfy one of two tests: the endpoint *only reads* and uses
/// a write method because its query lives in the body, or the endpoint is
/// self-service maintenance of the caller's own account. Nothing else belongs
/// here.
static READ_ONLY_ROUTES: &[ReadOnlyRoute] = &[
    // ---- Search: the query travels in the body, nothing is persisted ----
    // `/{org}/_search`
    ReadOnlyRoute {
        segments: &[Param, Lit("_search")],
        methods: &["POST"],
    },
    // `/{org}/_search_partition`
    ReadOnlyRoute {
        segments: &[Param, Lit("_search_partition")],
        methods: &["POST"],
    },
    // `/{org}/_search_stream`
    ReadOnlyRoute {
        segments: &[Param, Lit("_search_stream")],
        methods: &["POST"],
    },
    // `/{org}/_values_stream`
    ReadOnlyRoute {
        segments: &[Param, Lit("_values_stream")],
        methods: &["POST"],
    },
    // `/{org}/_search_multi`
    ReadOnlyRoute {
        segments: &[Param, Lit("_search_multi")],
        methods: &["POST"],
    },
    // `/{org}/_search_multi_stream`
    ReadOnlyRoute {
        segments: &[Param, Lit("_search_multi_stream")],
        methods: &["POST"],
    },
    // `/{org}/_search_partition_multi`
    ReadOnlyRoute {
        segments: &[Param, Lit("_search_partition_multi")],
        methods: &["POST"],
    },
    // `/{org}/_search_history` — reads the caller's own past searches.
    ReadOnlyRoute {
        segments: &[Param, Lit("_search_history")],
        methods: &["POST"],
    },
    // `/{org}/result_schema` — resolves the result schema of a query.
    ReadOnlyRoute {
        segments: &[Param, Lit("result_schema")],
        methods: &["POST"],
    },
    // `/{org}/{stream}/_around` — the v2 (POST) form of the context view.
    ReadOnlyRoute {
        segments: &[Param, Param, Lit("_around")],
        methods: &["POST"],
    },
    // ---- PromQL: the Prometheus HTTP API offers POST forms of its read
    // endpoints so long queries are not capped by URL length ----
    // `/{org}/prometheus/api/v1/{query,query_range,query_exemplars,series,labels,format_query}`
    ReadOnlyRoute {
        segments: &[
            Param,
            Lit("prometheus"),
            Lit("api"),
            Lit("v1"),
            Lit("query"),
        ],
        methods: &["POST"],
    },
    ReadOnlyRoute {
        segments: &[
            Param,
            Lit("prometheus"),
            Lit("api"),
            Lit("v1"),
            Lit("query_range"),
        ],
        methods: &["POST"],
    },
    ReadOnlyRoute {
        segments: &[
            Param,
            Lit("prometheus"),
            Lit("api"),
            Lit("v1"),
            Lit("query_exemplars"),
        ],
        methods: &["POST"],
    },
    ReadOnlyRoute {
        segments: &[
            Param,
            Lit("prometheus"),
            Lit("api"),
            Lit("v1"),
            Lit("series"),
        ],
        methods: &["POST"],
    },
    ReadOnlyRoute {
        segments: &[
            Param,
            Lit("prometheus"),
            Lit("api"),
            Lit("v1"),
            Lit("labels"),
        ],
        methods: &["POST"],
    },
    ReadOnlyRoute {
        segments: &[
            Param,
            Lit("prometheus"),
            Lit("api"),
            Lit("v1"),
            Lit("format_query"),
        ],
        methods: &["POST"],
    },
    // ---- Other reads that take a body ----
    // `/v2/{org}/alerts/{alert_id}/export` — returns the alert definition the
    // caller can already GET; the `/v2/` prefix is normalised away first.
    ReadOnlyRoute {
        segments: &[Param, Lit("alerts"), Param, Lit("export")],
        methods: &["POST"],
    },
    // `/{org}/sourcemaps/stacktrace` — symbolicates a stack trace against
    // already-stored source maps.
    ReadOnlyRoute {
        segments: &[Param, Lit("sourcemaps"), Lit("stacktrace")],
        methods: &["POST"],
    },
    // ---- Self-service: maintaining one's own account ----
    // `/{org}/users/{own_email}` — change own name/password. A read-only
    // account cannot touch anyone else's user record, and the users handler
    // separately refuses self role upgrades.
    ReadOnlyRoute {
        segments: &[Param, Lit("users"), SelfEmail],
        methods: &["PUT"],
    },
    // `/{org}/settings/v2/user/{own_email}` — own UI preferences.
    ReadOnlyRoute {
        segments: &[Param, Lit("settings"), Lit("v2"), Lit("user"), SelfEmail],
        methods: &["POST"],
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
        methods: &["DELETE"],
    },
];

/// The `/v2/...` API prefix, stripped before matching so `/v2/{org}/alerts/...`
/// classifies identically to `/{org}/alerts/...`.
const V2_API_PREFIX: &str = "v2";

/// HTTP methods that cannot mutate state and are therefore always allowed.
fn is_safe_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Does this segment pattern list match these path segments?
fn segments_match(patterns: &[Seg], columns: &[&str], user_email: &str) -> bool {
    if patterns.len() != columns.len() {
        return false;
    }
    patterns.iter().zip(columns).all(|(pat, col)| match pat {
        Seg::Lit(lit) => col == lit,
        Seg::Param => !col.is_empty(),
        Seg::SelfEmail => is_self_email(col, user_email),
    })
}

/// Does this path segment name the caller's own account?
///
/// Compared case-insensitively (emails are handled lowercased throughout the
/// auth path) and, failing that, after percent-decoding: clients disagree about
/// whether the `@` in an email is escaped inside a path segment — the frontend
/// escapes it on the per-user settings route and leaves it raw on the users
/// route — and the router decodes the segment either way, so this check has to
/// accept both spellings or it would refuse a read-only account access to its
/// own settings.
fn is_self_email(segment: &str, user_email: &str) -> bool {
    if segment.is_empty() || user_email.is_empty() {
        return false;
    }
    if segment.eq_ignore_ascii_case(user_email) {
        return true;
    }
    urlencoding::decode(segment).is_ok_and(|decoded| decoded.eq_ignore_ascii_case(user_email))
}

/// May a read-only account perform this request?
///
/// `path` is the request path with the `/api/` and base-uri prefix already
/// stripped, so it starts at `{org_id}`; a leading `/` and an optional `/v2/`
/// prefix are tolerated. `user_email` is the authenticated caller's email, used
/// only by the self-service rows.
///
/// Returns `true` for safe methods and for the routes declared in
/// [`READ_ONLY_ROUTES`]; `false` for everything else, which the caller turns
/// into a `403`.
pub fn is_request_allowed(method: &Method, path: &str, user_email: &str) -> bool {
    if is_safe_method(method) {
        return true;
    }

    let path = path.strip_prefix('/').unwrap_or(path);
    // Normalise the optional `/v2/{org}/...` prefix to `/{org}/...`.
    let path = path
        .strip_prefix(V2_API_PREFIX)
        .and_then(|rest| rest.strip_prefix('/'))
        .unwrap_or(path);

    let method = method.as_str();

    // A single trailing empty segment (trailing slash) is dropped so
    // `.../_search/` == `.../_search`.
    let mut columns: Vec<&str> = path.split('/').collect();
    if columns.len() > 1 && columns.last() == Some(&"") {
        columns.pop();
    }

    READ_ONLY_ROUTES.iter().any(|route| {
        route.methods.contains(&method) && segments_match(route.segments, &columns, user_email)
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
            // Dashboards, alerts, functions, pipelines, streams, users...
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
            // Ingestion is a write like any other.
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
        // Own profile.
        assert!(is_request_allowed(
            &Method::PUT,
            &format!("default/users/{ME}"),
            ME
        ));
        // Case differences in the path must not defeat the match.
        assert!(is_request_allowed(
            &Method::PUT,
            "default/users/Viewer@Example.com",
            ME
        ));
        // Somebody else's profile is a privileged write.
        assert!(!is_request_allowed(
            &Method::PUT,
            "default/users/someone.else@example.com",
            ME
        ));

        // Own per-user settings.
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
        // The frontend percent-encodes the email on the settings route, so the
        // escaped spelling has to match too — otherwise a read-only account
        // could not save its own UI preferences.
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

        // Org-level settings are not per-user settings.
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
        // Matching is positional: a stream literally named `_search` lands in a
        // `Param` slot and cannot make an ingestion route look like a search.
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
