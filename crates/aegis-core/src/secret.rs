//! A string that is wiped from memory on drop and never printed.
//!
//! `Serialize` exists only so the value can be written into the encrypted
//! vault. Views sent to the webview or MCP are separate types that never
//! contain a `Secret`.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// 24 random bytes as hex, for bearer tokens.
    pub fn random_token() -> Self {
        let mut bytes = Zeroizing::new([0u8; 24]);
        getrandom::fill(bytes.as_mut()).expect("the OS random number generator is unavailable");
        Self::new(hex::encode(bytes.as_ref()))
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::new(String::deserialize(d)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted_and_tokens_are_random() {
        let s = Secret::new("hunter22");
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
        let (a, b) = (Secret::random_token(), Secret::random_token());
        assert_eq!(a.expose().len(), 48);
        assert_ne!(a, b);
    }
}
