//! Small helpers shared by the core and the plugins.

use std::sync::{Mutex, MutexGuard};

/// Locks `m`, carrying on after a thread panicked while holding it. Every
/// value AegisWin keeps behind a mutex stays valid between statements, so a
/// panic elsewhere must not take the rest of the app down with it.
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
