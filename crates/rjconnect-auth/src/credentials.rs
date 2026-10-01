use std::fmt;

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum accepted identity byte length.
pub const MAX_IDENTITY_LENGTH: usize = 1024;
/// Maximum password length supported by the one-byte private PAP field.
pub const MAX_PASSWORD_LENGTH: usize = 255;

/// Validated wire credentials.
///
/// The caller is responsible for choosing the protocol encoding. The state
/// machine treats identity and password as opaque bytes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Credentials {
    identity: Vec<u8>,
    password: Vec<u8>,
}

impl Credentials {
    /// Creates validated credentials from wire-format bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when either field is empty or exceeds its protocol
    /// boundary.
    pub fn new(identity: Vec<u8>, password: Vec<u8>) -> Result<Self, CredentialError> {
        validate_length("identity", identity.len(), MAX_IDENTITY_LENGTH)?;
        validate_length("password", password.len(), MAX_PASSWORD_LENGTH)?;
        Ok(Self { identity, password })
    }

    /// Returns the non-secret EAP identity bytes.
    #[must_use]
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    pub(crate) fn password(&self) -> &[u8] {
        &self.password
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Credentials")
            .field("identity_length", &self.identity.len())
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Validation failure for credentials.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CredentialError {
    /// A required credential component is empty.
    #[error("{field} must not be empty")]
    Empty {
        /// Invalid field name.
        field: &'static str,
    },
    /// A credential component exceeds its configured boundary.
    #[error("{field} is too long: {actual} bytes, maximum {maximum}")]
    TooLong {
        /// Invalid field name.
        field: &'static str,
        /// Actual byte count.
        actual: usize,
        /// Maximum accepted byte count.
        maximum: usize,
    },
}

const fn validate_length(
    field: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), CredentialError> {
    if actual == 0 {
        return Err(CredentialError::Empty { field });
    }
    if actual > maximum {
        return Err(CredentialError::TooLong {
            field,
            actual,
            maximum,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_password() -> Result<(), CredentialError> {
        let credentials = Credentials::new(b"student".to_vec(), b"private".to_vec())?;
        let rendered = format!("{credentials:?}");

        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("private"));
        Ok(())
    }

    #[test]
    fn rejects_empty_password() {
        assert!(matches!(
            Credentials::new(b"student".to_vec(), Vec::new()),
            Err(CredentialError::Empty { field: "password" })
        ));
    }

    #[test]
    fn rejects_identity_over_product_boundary() {
        let identity = vec![b'a'; MAX_IDENTITY_LENGTH + 1];

        assert!(matches!(
            Credentials::new(identity, b"secret".to_vec()),
            Err(CredentialError::TooLong {
                field: "identity",
                actual,
                maximum: MAX_IDENTITY_LENGTH,
            }) if actual == MAX_IDENTITY_LENGTH + 1
        ));
    }

    #[test]
    fn rejects_password_that_cannot_fit_private_pap_length() {
        let password = vec![b'x'; MAX_PASSWORD_LENGTH + 1];

        assert!(matches!(
            Credentials::new(b"student".to_vec(), password),
            Err(CredentialError::TooLong {
                field: "password",
                actual,
                maximum: MAX_PASSWORD_LENGTH,
            }) if actual == MAX_PASSWORD_LENGTH + 1
        ));
    }
}
