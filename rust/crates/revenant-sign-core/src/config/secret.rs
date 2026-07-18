//! A string wrapper that never leaks its contents through `Debug`.
//!
//! Passwords live in memory as [`Secret`] rather than bare `String` so that an
//! accidental `dbg!`, `{:?}` format, panic message, or structured-log field
//! prints `[REDACTED]` instead of the credential. The plaintext is reachable
//! only through the explicit [`Secret::expose`] accessor, which reads as a
//! deliberate act at every call site.
//!
//! This is a deliberately minimal stand-in for `secrecy::SecretString`; it does
//! not yet zeroize on drop, since the same secret also flows as `&str` through
//! the keyring and SOAP APIs where its lifetime is not under our control.

use std::fmt;

/// An in-memory secret whose `Debug`/`Display` representations are redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Wrap a plaintext secret.
    pub fn new(value: impl Into<String>) -> Self {
        Secret(value.into())
    }

    /// Borrow the underlying plaintext. The explicit name makes secret access
    /// auditable -- grep for `.expose()` to find every use.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether the secret is the empty string.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Secret(value)
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Secret(value.to_owned())
    }
}

const REDACTED: &str = "[REDACTED]";

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn debug_is_redacted() {
        let secret = Secret::new("hunter2");
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
        assert_eq!(format!("{secret}"), "[REDACTED]");
    }

    #[test]
    fn expose_returns_plaintext() {
        let secret = Secret::new("hunter2");
        assert_eq!(secret.expose(), "hunter2");
        assert!(!secret.is_empty());
        assert!(Secret::new("").is_empty());
    }

    #[test]
    fn debug_of_container_does_not_leak() {
        // A struct holding a Secret must not leak it via derived Debug.
        #[derive(Debug)]
        struct Holder {
            #[allow(dead_code)]
            password: Secret,
        }
        let holder = Holder {
            password: Secret::new("s3cr3t"),
        };
        let rendered = format!("{holder:?}");
        assert!(!rendered.contains("s3cr3t"), "secret leaked: {rendered}");
        assert!(rendered.contains("[REDACTED]"));
    }
}
