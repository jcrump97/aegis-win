//! When to tell the owner about waiting approval requests while the window
//! is hidden (ADR 0004 §1.1), and fitting text into the tray tooltip.

use std::collections::HashSet;
use std::time::{Duration, Instant};

/// At most one tray balloon per this long; requests in between roll up.
pub const NOTIFY_GAP: Duration = Duration::from_secs(30);

/// Windows keeps 128 UTF-16 units of a tooltip, terminating zero included.
const TOOLTIP_UNITS: usize = 127;

/// Remembers which waiting requests the owner has been told about.
#[derive(Debug, Default)]
pub struct Notifier {
    seen: HashSet<String>,
    unannounced: bool,
    last: Option<Instant>,
}

impl Notifier {
    /// Called with every agent request now waiting. Returns how many are
    /// waiting when a new one arrived since the last notice and the last
    /// notice was at least [`NOTIFY_GAP`] ago.
    pub fn tick(&mut self, waiting: &[String], now: Instant) -> Option<usize> {
        self.seen.retain(|id| waiting.contains(id));
        let kept = self.seen.len();
        self.seen.extend(waiting.iter().cloned());
        if self.seen.len() > kept {
            self.unannounced = true;
        }
        if self.waiting_and_due(waiting.len(), now) {
            self.unannounced = false;
            self.last = Some(now);
            return Some(waiting.len());
        }
        None
    }

    fn waiting_and_due(&self, waiting: usize, now: Instant) -> bool {
        self.unannounced && waiting > 0 && self.last.is_none_or(|t| now.duration_since(t) >= NOTIFY_GAP)
    }
}

/// The balloon text for `n` waiting requests.
pub fn waiting_text(n: usize) -> String {
    if n == 1 {
        "1 request is waiting for your approval. Open AegisWin to review it.".into()
    } else {
        format!("{n} requests are waiting for your approval. Open AegisWin to review them.")
    }
}

/// Cuts `text` to what the tray tooltip can hold, ending with an ellipsis.
pub fn fit_tooltip(text: &str) -> String {
    if text.encode_utf16().count() <= TOOLTIP_UNITS {
        return text.to_owned();
    }
    let mut out = String::new();
    let mut units = 0;
    for c in text.chars() {
        if units + c.len_utf16() > TOOLTIP_UNITS - 1 {
            break;
        }
        units += c.len_utf16();
        out.push(c);
    }
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn notifies_once_per_gap_and_rolls_requests_up() {
        let mut n = Notifier::default();
        let t0 = Instant::now();
        assert_eq!(n.tick(&[], t0), None);
        assert_eq!(n.tick(&ids(&["a"]), t0), Some(1));
        assert_eq!(n.tick(&ids(&["a"]), t0 + NOTIFY_GAP), None, "nothing new");
        assert_eq!(n.tick(&ids(&["a", "b"]), t0 + Duration::from_secs(5)), None, "too soon");
        assert_eq!(n.tick(&ids(&["a", "b", "c"]), t0 + Duration::from_secs(10)), None);
        assert_eq!(n.tick(&ids(&["a", "b", "c"]), t0 + NOTIFY_GAP), Some(3), "rolled up");
        // Decided meanwhile: nothing to say.
        assert_eq!(n.tick(&ids(&["d"]), t0 + NOTIFY_GAP + Duration::from_secs(1)), None);
        assert_eq!(n.tick(&[], t0 + NOTIFY_GAP * 2), None, "nothing waits any more");
        assert_eq!(n.tick(&ids(&["e"]), t0 + NOTIFY_GAP * 3), Some(1));
    }

    #[test]
    fn tooltips_fit_the_windows_limit() {
        assert_eq!(fit_tooltip("AegisWin: unlocked"), "AegisWin: unlocked");
        let long = format!("AegisWin: unlocked, running {}", "é".repeat(200));
        let fitted = fit_tooltip(&long);
        assert_eq!(fitted.encode_utf16().count(), 127);
        assert!(fitted.ends_with('…'));
        let emoji = "🛡".repeat(100);
        assert!(fit_tooltip(&emoji).encode_utf16().count() <= 127, "never splits a surrogate pair");
        assert_eq!(waiting_text(1), "1 request is waiting for your approval. Open AegisWin to review it.");
    }
}
