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

//! Positional route matching, shared by the declarative route tables in this
//! module ([`super::ingestion_routes`] and [`super::read_only_routes`]).
//!
//! Both tables answer an authorization question by matching a request against
//! declared `(path shape, methods)` rows, and both must normalise the request
//! path the same way to be sound. Historically the auth layer matched paths by
//! substring — which is what let an ingestion token read protected data on
//! `GET /{org}/{stream}/traces/latest`, GHSA-wffq-g8qf-ccmv. Matching here is
//! *positional* instead: a stream literally named `traces` only ever lands in a
//! [`Seg::Param`] slot and can never be mistaken for the `traces` keyword.
//!
//! Keeping the matcher in one place is deliberate: two copies of these
//! normalisation rules would drift, and a fix applied to one table would
//! silently miss the other.

/// One segment of a declared route pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Seg {
    /// A fixed path segment that must match exactly (e.g. `_bulk`, `traces`).
    Lit(&'static str),
    /// A single path parameter — matches any one non-empty segment
    /// (`{org_id}`, `{stream_name}`, `{name}`, ...). It deliberately does NOT
    /// match a keyword by accident because matching is positional.
    Param,
    /// A single path parameter constrained to the caller-supplied *subject*
    /// (see `subject_matches` on [`segments_match`]) — e.g. "this must be the
    /// caller's own account". A table that supplies no subject predicate can
    /// never match this pattern, so it fails closed.
    Subject,
}

/// The `/v2/...` API prefix, stripped before matching so `/v2/{org}/_bulk`
/// classifies identically to `/{org}/_bulk`.
const V2_API_PREFIX: &str = "v2";

/// Strip the leading `/` and an optional `/v2/` prefix, leaving a path that
/// starts at `{org_id}`.
///
/// Returned as a `&str` rather than pre-split segments so callers that need to
/// distinguish a trailing slash (e.g. the Elasticsearch root ping `GET /{org}/`)
/// can still see it.
pub(crate) fn strip_api_prefixes(path: &str) -> &str {
    let path = path.strip_prefix('/').unwrap_or(path);
    path.strip_prefix(V2_API_PREFIX)
        .and_then(|rest| rest.strip_prefix('/'))
        .unwrap_or(path)
}

/// Split a prefix-stripped path into the segments used for matching.
///
/// A single trailing empty segment (trailing slash) is dropped, so
/// `.../_bulk/` matches the same row as `.../_bulk`.
pub(crate) fn columns(path: &str) -> Vec<&str> {
    path.strip_suffix('/').unwrap_or(path).split('/').collect()
}

/// Does this segment pattern list match these path segments?
///
/// `subject_matches` decides [`Seg::Subject`] segments; pass `|_| false` from
/// tables that declare no subject-constrained routes.
pub(crate) fn segments_match(
    patterns: &[Seg],
    columns: &[&str],
    subject_matches: impl Fn(&str) -> bool,
) -> bool {
    if patterns.len() != columns.len() {
        return false;
    }
    patterns.iter().zip(columns).all(|(pat, col)| match pat {
        Seg::Lit(lit) => col == lit,
        // A param matches any single non-empty segment.
        Seg::Param => !col.is_empty(),
        Seg::Subject => subject_matches(col),
    })
}

#[cfg(test)]
mod tests {
    use super::{Seg::*, *};

    #[test]
    fn strips_leading_slash_and_v2_prefix() {
        assert_eq!(strip_api_prefixes("default/_bulk"), "default/_bulk");
        assert_eq!(strip_api_prefixes("/default/_bulk"), "default/_bulk");
        assert_eq!(strip_api_prefixes("/v2/default/_bulk"), "default/_bulk");
        // `v2` as an org name is not a prefix — it has no following slash to
        // strip beyond its own, so the org survives.
        assert_eq!(strip_api_prefixes("/v2suffix/_bulk"), "v2suffix/_bulk");
    }

    #[test]
    fn drops_a_single_trailing_empty_segment() {
        assert_eq!(columns("a/b"), vec!["a", "b"]);
        assert_eq!(columns("a/b/"), vec!["a", "b"]);
        assert_eq!(columns("a//"), vec!["a", ""]);
        assert_eq!(columns(""), vec![""]);
    }

    #[test]
    fn matching_is_positional_and_length_exact() {
        let pattern = &[Param, Lit("traces"), Lit("latest")];
        assert!(segments_match(
            pattern,
            &["default", "traces", "latest"],
            |_| false
        ));
        // A stream *named* `traces` cannot impersonate the keyword slot.
        assert!(!segments_match(pattern, &["default", "traces"], |_| false));
        assert!(!segments_match(
            pattern,
            &["default", "traces", "latest", "extra"],
            |_| false
        ));
        // A param never matches an empty segment.
        assert!(!segments_match(&[Param], &[""], |_| false));
    }

    #[test]
    fn subject_segments_fail_closed_without_a_predicate() {
        assert!(!segments_match(&[Subject], &["me@example.com"], |_| false));
        assert!(segments_match(&[Subject], &["me@example.com"], |col| col
            == "me@example.com"));
    }
}
