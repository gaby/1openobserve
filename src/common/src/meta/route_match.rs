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

//! Positional route matching, shared by [`super::ingestion_routes`] and
//! [`super::read_only_routes`] so their normalisation rules cannot drift.
//!
//! Positional rather than substring matching: substring matching is what let an
//! ingestion token read `GET /{org}/{stream}/traces/latest` (GHSA-wffq-g8qf-ccmv).
//! A stream named `traces` only ever lands in a [`Seg::Param`] slot.

/// One segment of a declared route pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Seg {
    /// A fixed path segment that must match exactly (e.g. `_bulk`, `traces`).
    Lit(&'static str),
    /// Any one non-empty segment (`{org_id}`, `{stream_name}`, ...).
    Param,
    /// A segment constrained to the caller-supplied subject (see
    /// `subject_matches` on [`segments_match`]). Fails closed without one.
    Subject,
}

/// Stripped before matching, so `/v2/{org}/_bulk` matches `/{org}/_bulk`.
const V2_API_PREFIX: &str = "v2";

/// Strip the leading `/` and any `/v2/` prefix, leaving a path at `{org_id}`.
/// Returns a `&str` so callers can still see a trailing slash (e.g. the
/// Elasticsearch root ping `GET /{org}/`).
pub(crate) fn strip_api_prefixes(path: &str) -> &str {
    let path = path.strip_prefix('/').unwrap_or(path);
    path.strip_prefix(V2_API_PREFIX)
        .and_then(|rest| rest.strip_prefix('/'))
        .unwrap_or(path)
}

/// Split a prefix-stripped path for matching, dropping one trailing slash.
pub(crate) fn columns(path: &str) -> Vec<&str> {
    path.strip_suffix('/').unwrap_or(path).split('/').collect()
}

/// `subject_matches` decides [`Seg::Subject`] segments; pass `|_| false` from
/// tables with no subject-constrained routes.
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
        // `v2` as an org name is not a prefix.
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
        assert!(!segments_match(pattern, &["default", "traces"], |_| false));
        assert!(!segments_match(
            pattern,
            &["default", "traces", "latest", "extra"],
            |_| false
        ));
        assert!(!segments_match(&[Param], &[""], |_| false));
    }

    #[test]
    fn subject_segments_fail_closed_without_a_predicate() {
        assert!(!segments_match(&[Subject], &["me@example.com"], |_| false));
        assert!(segments_match(&[Subject], &["me@example.com"], |col| col
            == "me@example.com"));
    }
}
