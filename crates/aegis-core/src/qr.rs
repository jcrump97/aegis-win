//! A QR code drawn as one SVG path, for the device page link
//! (ADR 0004 §1.2). The UI builds the `<svg>` element itself.

use qrcodegen::{QrCode, QrCodeEcc};
use serde::Serialize;

/// Light modules around the code, as the QR standard asks.
const QUIET_ZONE: i32 = 4;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrView {
    /// Width and height in modules, quiet zone included (the SVG viewBox).
    pub size: i32,
    /// One `M x y h1v1h-1z` square per dark module.
    pub path: String,
}

/// Encodes `text`, or `None` when it is too long for any QR version.
pub fn encode(text: &str) -> Option<QrView> {
    let qr = QrCode::encode_text(text, QrCodeEcc::Medium).ok()?;
    let mut path = String::new();
    for y in 0..qr.size() {
        for x in 0..qr.size() {
            if qr.get_module(x, y) {
                path.push_str(&format!("M{} {}h1v1h-1z", x + QUIET_ZONE, y + QUIET_ZONE));
            }
        }
    }
    Some(QrView { size: qr.size() + 2 * QUIET_ZONE, path })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draws_a_url() {
        let qr = encode("http://192.168.100.200:8787/approve/0123456789abcdef0123456789abcdef").unwrap();
        let modules = qr.size - 8;
        assert!(modules >= 21 && (modules - 21) % 4 == 0, "a QR size plus the quiet zone: {}", qr.size);
        assert!(qr.path.starts_with("M4 4h1v1h-1z"), "the top-left finder pattern");
        assert!(qr.path.bytes().all(|b| b.is_ascii_digit() || b" Mhvz-".contains(&b)));
    }
}
