// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::collections::HashMap;

use crate::extensions::raw_credentials::Credential;
use crate::hooks::payload::Extensions;
use crate::http_credential;

/// Where the credential sits, and what marks it as this resolver's.
///
/// Use a prefix to select which resolver handles a credential when several
/// key populations share a route. The prefix may include an auth scheme,
/// which is stripped before the key is presented for lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialLocation {
    /// The wire location.
    pub credential: Credential,

    /// What the value must start with to be one this resolver services.
    ///
    /// A prefix such as `Bearer sk-oai-` accepts `Bearer sk-oai-abc` and
    /// yields `sk-oai-abc`. The auth scheme is case-insensitive and separated
    /// from the key by one or more spaces per [RFC 9110 Section 11.1]. The
    /// key leader is case-sensitive and stays in the presented credential.
    /// A prefix without a space is entirely a key leader. `None` accepts
    /// every value at the configured location.
    ///
    /// [RFC 9110 Section 11.1]: https://datatracker.ietf.org/doc/html/rfc9110#section-11.1
    pub prefix: Option<String>,
}

/// Why a configured credential location did not yield a credential.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
pub enum ExtractionError {
    /// Nothing was supplied at the configured location.
    ///
    /// Denies as `auth.missing_credential`.
    Missing,

    /// The location held a value and it was empty.
    ///
    /// Denies as `auth.empty_credential`.
    Empty,

    /// The location held a value that does not carry this resolver's
    /// prefix.
    ///
    /// This resolver declines without denying the request, so another
    /// resolver can handle the credential.
    WrongPrefix,

    /// The credential name appeared more than once, or multiple
    /// same-logical-header entries with different casing exist.
    ///
    /// Denies as `auth.ambiguous_credential`.
    Ambiguous,

    /// The credential input is structurally malformed — a parse
    /// failure that is neither missing nor ambiguous.
    ///
    /// Denies as `auth.malformed_credential`.
    Malformed,
}

fn strip_prefix_ignore_case<'v>(value: &'v str, prefix: &str) -> Option<&'v str> {
    let (head, tail) = value.split_at_checked(prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then_some(tail)
}

fn map_parse_error(e: http_credential::CredentialParseError) -> ExtractionError {
    use http_credential::CredentialParseError;
    match e {
        CredentialParseError::Duplicate { .. } => ExtractionError::Ambiguous,
        _ => ExtractionError::Malformed,
    }
}

fn single_header_ci<'h>(
    headers: &'h HashMap<String, String>,
    name: &str,
) -> Result<&'h str, ExtractionError> {
    let mut matches = headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str());

    match (matches.next(), matches.next()) {
        (None, _) => Err(ExtractionError::Missing),
        (Some(value), None) => Ok(value),
        (Some(_), Some(_)) => Err(ExtractionError::Ambiguous),
    }
}

impl CredentialLocation {
    /// Pair a location with the prefix that gates it.
    pub fn new(credential: Credential, prefix: Option<String>) -> Self {
        Self { credential, prefix }
    }

    /// The name of the wire location, whatever kind it is.
    pub fn name(&self) -> &str {
        match &self.credential {
            Credential::Header { name }
            | Credential::Cookie { name }
            | Credential::QueryParam { name } => name,
        }
    }

    /// Read a credential from headers or a raw query string. Header names
    /// are matched without ASCII case; the configured prefix selects which
    /// credentials this resolver handles.
    ///
    /// # Errors
    ///
    /// Returns an [`ExtractionError`] when the credential is missing,
    /// empty, ambiguous, malformed, or belongs to another resolver.
    pub fn raw(
        &self,
        headers: &HashMap<String, String>,
        raw_query_string: Option<&str>,
    ) -> Result<String, ExtractionError> {
        match &self.credential {
            Credential::Header { name } => self.extract_header(headers, name),
            Credential::Cookie { name } => self.extract_cookie(headers, name),
            Credential::QueryParam { name } => self.extract_query_param(raw_query_string, name),
        }
    }

    fn extract_header(
        &self,
        headers: &HashMap<String, String>,
        name: &str,
    ) -> Result<String, ExtractionError> {
        let raw = single_header_ci(headers, name)?;
        self.gate(raw).map(str::to_owned)
    }

    fn extract_cookie(
        &self,
        headers: &HashMap<String, String>,
        name: &str,
    ) -> Result<String, ExtractionError> {
        let cookie_header = single_header_ci(headers, "cookie")?;

        let cookies =
            http_credential::parse_cookie_header(cookie_header, name).map_err(map_parse_error)?;

        match cookies.get(name) {
            None => Err(ExtractionError::Missing),
            Some(v) => self.gate(v).map(str::to_owned),
        }
    }

    fn extract_query_param(
        &self,
        raw_query_string: Option<&str>,
        name: &str,
    ) -> Result<String, ExtractionError> {
        let Some(qs) = raw_query_string else {
            return Err(ExtractionError::Missing);
        };

        let params = http_credential::parse_query_string(qs, name).map_err(map_parse_error)?;

        match params.get(name) {
            None => Err(ExtractionError::Missing),
            Some(v) => self.gate(v).map(str::to_owned),
        }
    }

    fn gate<'v>(&self, raw: &'v str) -> Result<&'v str, ExtractionError> {
        if raw.is_empty() {
            return Err(ExtractionError::Empty);
        }
        let after = match self.prefix.as_deref() {
            Some(prefix) => Self::strip_gate(raw, prefix)?,
            None => raw,
        };
        if after.is_empty() {
            return Err(ExtractionError::Empty);
        }
        Ok(after)
    }

    fn strip_gate<'v>(raw: &'v str, prefix: &str) -> Result<&'v str, ExtractionError> {
        let Some((scheme, leader)) = prefix.split_once(' ') else {
            return raw
                .starts_with(prefix)
                .then_some(raw)
                .ok_or(ExtractionError::WrongPrefix);
        };

        let after_scheme =
            strip_prefix_ignore_case(raw, scheme).ok_or(ExtractionError::WrongPrefix)?;
        let credential = after_scheme.trim_start_matches(' ');
        if credential.len() == after_scheme.len() {
            return Err(ExtractionError::WrongPrefix);
        }

        credential
            .starts_with(leader.trim_start_matches(' '))
            .then_some(credential)
            .ok_or(ExtractionError::WrongPrefix)
    }

    /// Read a credential using the query string in `Extensions.http.query`.
    ///
    /// # Errors
    ///
    /// Returns an [`ExtractionError`] when the credential is missing,
    /// empty, ambiguous, malformed, or belongs to another resolver.
    pub fn raw_from_ext(
        &self,
        headers: &HashMap<String, String>,
        ext: &Extensions,
    ) -> Result<String, ExtractionError> {
        let query = ext.http.as_ref().and_then(|h| h.query.as_deref());
        self.raw(headers, query)
    }

    /// Validate a credential name and optional prefix before use.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty name or prefix, invalid name
    /// characters, or a prefix starting with a space.
    pub fn validate(&self) -> Result<(), String> {
        let (kind, name) = match &self.credential {
            Credential::Header { name } => ("header", name.as_str()),
            Credential::Cookie { name } => ("cookie", name.as_str()),
            Credential::QueryParam { name } => ("query_param", name.as_str()),
        };

        if name.trim().is_empty() {
            return Err(format!(
                "`credential: {{ kind: {kind} }}` name must be non-empty"
            ));
        }
        if name != name.trim() || name.contains(char::is_whitespace) {
            return Err(format!(
                "`credential: {{ kind: {kind}, name: '{name}' }}` \
                 must not contain leading, trailing, or interior whitespace"
            ));
        }
        if matches!(self.credential, Credential::Cookie { .. }) && name.contains(['=', ';']) {
            return Err(format!(
                "`credential: {{ kind: cookie, name: '{name}' }}` must not contain '=' or ';'"
            ));
        }
        if matches!(self.credential, Credential::QueryParam { .. }) && name.contains(['&', '=']) {
            return Err(format!(
                "`credential: {{ kind: query_param, name: '{name}' }}` \
                 must not contain '&' or '='"
            ));
        }
        if matches!(
            self.credential,
            Credential::Header { .. } | Credential::Cookie { .. }
        ) && http::header::HeaderName::from_bytes(name.as_bytes()).is_err()
        {
            return Err(format!(
                "`credential: {{ kind: {kind}, name: '{name}' }}` must be a valid HTTP token"
            ));
        }
        if self.prefix.as_ref().is_some_and(String::is_empty) {
            return Err(format!(
                "{}: `prefix` is present and empty, which gates nothing. Remove it to accept \
                 every value at this location",
                self.credential
            ));
        }
        if self.prefix.as_ref().is_some_and(|p| p.starts_with(' ')) {
            return Err(format!(
                "{}: `prefix` starts with a space, which no value can match",
                self.credential
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::get_unwrap,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn new_constructs_with_all_credential_variants() {
        let header = CredentialLocation::new(
            Credential::Header {
                name: "Authorization".into(),
            },
            Some("Bearer ".into()),
        );
        assert_eq!(header.name(), "Authorization");

        let cookie = CredentialLocation::new(
            Credential::Cookie {
                name: "__Host-jwt".into(),
            },
            None,
        );
        assert_eq!(cookie.name(), "__Host-jwt");

        let query = CredentialLocation::new(
            Credential::QueryParam {
                name: "access_token".into(),
            },
            None,
        );
        assert_eq!(query.name(), "access_token");
    }

    // -----------------------------------------------------------------------------
    // RFC 9110 Section 11.1
    // -----------------------------------------------------------------------------
    /// Scheme matching follows [RFC 9110 Section 11.1].
    ///
    /// [RFC 9110 Section 11.1]: https://datatracker.ietf.org/doc/html/rfc9110#section-11.1
    #[test]
    fn strip_prefix_ignore_case_preserves_existing_behavior() {
        assert_eq!(
            strip_prefix_ignore_case("Bearer tok", "Bearer"),
            Some(" tok")
        );
        assert_eq!(
            strip_prefix_ignore_case("bearer tok", "Bearer"),
            Some(" tok")
        );
        assert_eq!(
            strip_prefix_ignore_case("BEARER tok", "Bearer"),
            Some(" tok")
        );
        assert_eq!(strip_prefix_ignore_case("Basic tok", "Bearer"), None);
        assert_eq!(strip_prefix_ignore_case("Be", "Bearer"), None);
    }

    // -----------------------------------------------------------------------------
    // RFC 9110 Section 11.1
    // -----------------------------------------------------------------------------
    /// Scheme matching follows [RFC 9110 Section 11.1].
    ///
    /// [RFC 9110 Section 11.1]: https://datatracker.ietf.org/doc/html/rfc9110#section-11.1
    #[test]
    fn prefix_gate_scheme_only() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "Authorization".into(),
            },
            Some("Bearer ".into()),
        );
        assert_eq!(loc.gate("Bearer tok").unwrap(), "tok");
        assert_eq!(loc.gate("bearer tok").unwrap(), "tok");
        assert_eq!(loc.gate("bearer   tok").unwrap(), "tok");
        assert_eq!(loc.gate("Basic tok"), Err(ExtractionError::WrongPrefix));
    }

    #[test]
    fn prefix_gate_leader_only() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "x-api-key".into(),
            },
            Some("sk-oai-".into()),
        );
        assert_eq!(loc.gate("sk-oai-abc").unwrap(), "sk-oai-abc");
        assert_eq!(loc.gate("pk-live-abc"), Err(ExtractionError::WrongPrefix));
    }

    // -----------------------------------------------------------------------------
    // RFC 9110 Section 11.1
    // -----------------------------------------------------------------------------
    /// Scheme matching follows [RFC 9110 Section 11.1].
    ///
    /// [RFC 9110 Section 11.1]: https://datatracker.ietf.org/doc/html/rfc9110#section-11.1
    #[test]
    fn prefix_gate_scheme_plus_leader() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "Authorization".into(),
            },
            Some("Bearer sk-oai-".into()),
        );
        assert_eq!(loc.gate("Bearer sk-oai-abc").unwrap(), "sk-oai-abc");
        assert_eq!(loc.gate("bearer sk-oai-abc").unwrap(), "sk-oai-abc");
        assert_eq!(
            loc.gate("Bearer pk-live-abc"),
            Err(ExtractionError::WrongPrefix)
        );
    }

    #[test]
    fn prefix_gate_no_prefix() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "x-api-key".into(),
            },
            None,
        );
        assert_eq!(loc.gate("any-value").unwrap(), "any-value");
        assert_eq!(loc.gate(""), Err(ExtractionError::Empty));
    }

    #[test]
    fn header_extraction_round_trip() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "Authorization".into(),
            },
            Some("Bearer ".into()),
        );
        let mut headers = HashMap::new();
        headers.insert("authorization".to_owned(), "Bearer my-jwt".to_owned());

        assert_eq!(loc.raw(&headers, None).unwrap(), "my-jwt");
    }

    #[test]
    fn header_extraction_missing() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "Authorization".into(),
            },
            None,
        );
        let headers = HashMap::new();
        assert_eq!(loc.raw(&headers, None), Err(ExtractionError::Missing));
    }

    #[test]
    fn header_extraction_empty() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "x-api-key".into(),
            },
            None,
        );
        let mut headers = HashMap::new();
        headers.insert("x-api-key".to_owned(), String::new());
        assert_eq!(loc.raw(&headers, None), Err(ExtractionError::Empty));
    }

    #[test]
    fn header_extraction_empty_with_prefix() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "Authorization".into(),
            },
            Some("Bearer ".into()),
        );
        let headers = HashMap::from([("Authorization".to_owned(), String::new())]);
        assert_eq!(loc.raw(&headers, None), Err(ExtractionError::Empty));
    }

    #[test]
    fn cookie_extraction_happy_path() {
        let loc = CredentialLocation::new(
            Credential::Cookie {
                name: "__Host-jwt".into(),
            },
            None,
        );
        let mut headers = HashMap::new();
        headers.insert(
            "cookie".to_owned(),
            "analytics=x; __Host-jwt=eyJ.tok.sig; theme=dark".to_owned(),
        );
        assert_eq!(loc.raw(&headers, None).unwrap(), "eyJ.tok.sig");
    }

    #[test]
    fn cookie_extraction_missing_cookie_header() {
        let loc = CredentialLocation::new(
            Credential::Cookie {
                name: "__Host-jwt".into(),
            },
            None,
        );
        let headers = HashMap::new();
        assert_eq!(loc.raw(&headers, None), Err(ExtractionError::Missing));
    }

    #[test]
    fn cookie_extraction_missing_credential_cookie() {
        let loc = CredentialLocation::new(
            Credential::Cookie {
                name: "__Host-jwt".into(),
            },
            None,
        );
        let mut headers = HashMap::new();
        headers.insert("cookie".to_owned(), "analytics=x; theme=dark".to_owned());
        assert_eq!(loc.raw(&headers, None), Err(ExtractionError::Missing));
    }

    #[test]
    fn cookie_extraction_empty_value() {
        let loc = CredentialLocation::new(
            Credential::Cookie {
                name: "session".into(),
            },
            None,
        );
        let mut headers = HashMap::new();
        headers.insert("cookie".to_owned(), "session=".to_owned());
        assert_eq!(loc.raw(&headers, None), Err(ExtractionError::Empty));
    }

    #[test]
    fn query_param_extraction_happy_path() {
        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "access_token".into(),
            },
            None,
        );
        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());
        assert_eq!(
            loc.raw(&headers, Some("page=1&access_token=eyJ.tok&limit=10"))
                .unwrap(),
            "eyJ.tok"
        );
    }

    #[test]
    fn query_param_extraction_no_query_string() {
        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "access_token".into(),
            },
            None,
        );
        let headers = HashMap::new();
        assert_eq!(loc.raw(&headers, None), Err(ExtractionError::Missing));
    }

    #[test]
    fn query_param_extraction_missing_param() {
        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "access_token".into(),
            },
            None,
        );
        let headers = HashMap::new();
        assert_eq!(
            loc.raw(&headers, Some("page=1&limit=10")),
            Err(ExtractionError::Missing)
        );
    }

    #[test]
    fn query_param_extraction_empty_value() {
        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "access_token".into(),
            },
            None,
        );
        let headers = HashMap::new();
        assert_eq!(
            loc.raw(&headers, Some("access_token=")),
            Err(ExtractionError::Empty)
        );
    }

    #[test]
    fn validate_accepts_all_variants() {
        for cred in [
            Credential::Header {
                name: "Authorization".into(),
            },
            Credential::Cookie {
                name: "__Host-jwt".into(),
            },
            Credential::QueryParam {
                name: "access_token".into(),
            },
        ] {
            let loc = CredentialLocation::new(cred, None);
            loc.validate().unwrap();
        }
    }

    #[test]
    fn validate_rejects_empty_name() {
        for cred in [
            Credential::Header {
                name: String::new(),
            },
            Credential::Cookie { name: "  ".into() },
            Credential::QueryParam {
                name: String::new(),
            },
        ] {
            let loc = CredentialLocation::new(cred, None);
            assert!(loc.validate().is_err());
        }
    }

    #[test]
    fn validate_rejects_whitespace_in_name() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "X Api Key".into(),
            },
            None,
        );
        assert!(loc.validate().is_err());

        let loc = CredentialLocation::new(
            Credential::Header {
                name: " Authorization".into(),
            },
            None,
        );
        assert!(loc.validate().is_err());
    }

    #[test]
    fn validate_rejects_non_token_header_and_cookie_names() {
        for credential in [
            Credential::Header {
                name: "bad:name".into(),
            },
            Credential::Cookie {
                name: "bad/name".into(),
            },
        ] {
            let error = CredentialLocation::new(credential, None)
                .validate()
                .unwrap_err();
            assert!(error.contains("valid HTTP token"), "got: {error}");
        }
    }

    #[test]
    fn validate_rejects_cookie_with_equals_or_semicolon() {
        let loc = CredentialLocation::new(
            Credential::Cookie {
                name: "bad=name".into(),
            },
            None,
        );
        assert!(loc.validate().is_err());

        let loc = CredentialLocation::new(
            Credential::Cookie {
                name: "bad;name".into(),
            },
            None,
        );
        assert!(loc.validate().is_err());
    }

    #[test]
    fn validate_rejects_query_param_with_ampersand_or_equals() {
        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "bad&name".into(),
            },
            None,
        );
        assert!(loc.validate().is_err());

        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "bad=name".into(),
            },
            None,
        );
        assert!(loc.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_prefix() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "Authorization".into(),
            },
            Some(String::new()),
        );
        assert!(loc.validate().is_err());
    }

    #[test]
    fn validate_rejects_leading_space_prefix() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "Authorization".into(),
            },
            Some(" Bearer".into()),
        );
        assert!(loc.validate().is_err());
    }

    #[test]
    fn header_duplicate_casing_returns_ambiguous() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "Authorization".into(),
            },
            None,
        );
        let mut headers = HashMap::new();
        headers.insert("authorization".to_owned(), "Bearer tok1".to_owned());
        headers.insert("Authorization".to_owned(), "Bearer tok2".to_owned());
        assert_eq!(loc.raw(&headers, None), Err(ExtractionError::Ambiguous));
    }

    #[test]
    fn cookie_duplicate_header_casing_returns_ambiguous() {
        let loc = CredentialLocation::new(
            Credential::Cookie {
                name: "session".into(),
            },
            None,
        );
        let mut headers = HashMap::new();
        headers.insert("cookie".to_owned(), "session=abc".to_owned());
        headers.insert("Cookie".to_owned(), "session=def".to_owned());
        assert_eq!(loc.raw(&headers, None), Err(ExtractionError::Ambiguous));
    }

    #[test]
    fn cookie_duplicate_credential_name_returns_ambiguous() {
        let loc = CredentialLocation::new(Credential::Cookie { name: "jwt".into() }, None);
        let mut headers = HashMap::new();
        headers.insert("cookie".to_owned(), "jwt=a; jwt=b".to_owned());
        assert_eq!(loc.raw(&headers, None), Err(ExtractionError::Ambiguous));
    }

    #[test]
    fn query_param_duplicate_name_returns_ambiguous() {
        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "token".into(),
            },
            None,
        );
        let headers = HashMap::new();
        assert_eq!(
            loc.raw(&headers, Some("token=a&token=b")),
            Err(ExtractionError::Ambiguous)
        );
    }

    #[test]
    fn query_param_percent_encoded_name_returns_malformed() {
        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "access_token".into(),
            },
            None,
        );
        let headers = HashMap::new();
        assert_eq!(
            loc.raw(&headers, Some("access%5Ftoken=eyJ.tok")),
            Err(ExtractionError::Malformed)
        );
    }

    #[test]
    fn cookie_control_character_returns_malformed() {
        let loc = CredentialLocation::new(Credential::Cookie { name: "jwt".into() }, None);
        let mut headers = HashMap::new();
        headers.insert("cookie".to_owned(), "jwt=a\r\nInjected: header".to_owned());
        assert_eq!(loc.raw(&headers, None), Err(ExtractionError::Malformed));
    }

    #[test]
    fn cookie_extraction_with_prefix_gate() {
        let loc = CredentialLocation::new(
            Credential::Cookie {
                name: "api_key".into(),
            },
            Some("sk-oai-".into()),
        );
        let mut headers = HashMap::new();
        headers.insert("cookie".to_owned(), "api_key=sk-oai-secret".to_owned());
        assert_eq!(loc.raw(&headers, None).unwrap(), "sk-oai-secret");
    }

    #[test]
    fn query_param_extraction_with_prefix_gate() {
        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "token".into(),
            },
            Some("sk-".into()),
        );
        let headers = HashMap::new();
        assert_eq!(
            loc.raw(&headers, Some("token=sk-abc123")).unwrap(),
            "sk-abc123"
        );
    }

    #[test]
    fn query_param_wrong_prefix_returns_wrong_prefix() {
        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "token".into(),
            },
            Some("sk-".into()),
        );
        let headers = HashMap::new();
        assert_eq!(
            loc.raw(&headers, Some("token=pk-abc123")),
            Err(ExtractionError::WrongPrefix)
        );
    }

    #[test]
    fn oversize_cookie_returns_malformed() {
        let loc = CredentialLocation::new(Credential::Cookie { name: "jwt".into() }, None);
        let mut headers = HashMap::new();
        let oversize = format!("jwt={}", "x".repeat(16 * 1024 + 1));
        headers.insert("cookie".to_owned(), oversize);
        assert_eq!(loc.raw(&headers, None), Err(ExtractionError::Malformed));
    }

    #[test]
    fn oversize_query_string_returns_malformed() {
        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "token".into(),
            },
            None,
        );
        let headers = HashMap::new();
        let oversize = format!("token={}", "x".repeat(16 * 1024 + 1));
        assert_eq!(
            loc.raw(&headers, Some(&oversize)),
            Err(ExtractionError::Malformed)
        );
    }

    #[test]
    fn query_param_empty_string_is_missing() {
        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "token".into(),
            },
            None,
        );
        let headers = HashMap::new();
        assert_eq!(
            loc.raw(&headers, Some("")),
            Err(ExtractionError::Missing),
            "an empty query string has no parameters"
        );
    }
}
