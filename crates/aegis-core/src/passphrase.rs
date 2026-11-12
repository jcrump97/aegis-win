//! A strength guide for a vault passphrase the owner types (ADR 0004 §3.2).
//! Generated word passphrases are made in the app window (`src/ui/passphrase.ts`),
//! so a new passphrase never travels in an `invoke` response.
//!
//! The guide is advice only. The rule the vault enforces is the length
//! minimum in [`crate::vault::MIN_PASSPHRASE_LEN`].

use serde::Serialize;

/// What the setup screen shows under a passphrase the owner types.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Strength {
    /// zxcvbn's score, 0 (guessable) to 4 (very hard to guess).
    pub score: u8,
    /// About how many guesses an attacker needs, as bits (log2).
    pub bits: u32,
    /// Long enough for the vault (the enforced rule).
    pub long_enough: bool,
    pub warning: Option<String>,
    pub suggestions: Vec<String>,
}

/// Rates a passphrase. Nothing is stored or logged.
pub fn strength(passphrase: &str) -> Strength {
    let long_enough = crate::vault::meets_passphrase_rule(passphrase);
    if passphrase.is_empty() {
        return Strength { score: 0, bits: 0, long_enough, warning: None, suggestions: Vec::new() };
    }
    // zxcvbn slows down on very long input; past 100 characters the score is 4 anyway.
    let sample: String = passphrase.chars().take(100).collect();
    let e = zxcvbn::zxcvbn(&sample, &["aegis", "aegiswin", "windows"]);
    let feedback = e.feedback();
    Strength {
        score: u8::from(e.score()),
        bits: (e.guesses_log10() * std::f64::consts::LOG2_10).floor().max(0.0) as u32,
        long_enough,
        warning: feedback.and_then(|f| f.warning()).map(|w| w.to_string()),
        suggestions: feedback.map(|f| f.suggestions().iter().map(ToString::to_string).collect()).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_weak_and_strong_passphrases() {
        let weak = strength("password1234");
        assert!(weak.score <= 1 && !weak.long_enough);
        assert!(weak.warning.is_some() || !weak.suggestions.is_empty());
        let strong = strength("cradle-unpaid-vivid-otter-sprout");
        assert_eq!(strong.score, 4);
        assert!(strong.long_enough && strong.bits >= 60);
        assert_eq!(strength("").score, 0);
        // Very long input is cut before rating.
        assert!(strength(&"a1-b2-".repeat(200)).long_enough);
    }
}
