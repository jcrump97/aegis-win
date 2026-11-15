//! Restart as administrator, with the launch, the install claim and the quit
//! passed in so every path can be tested without a UAC prompt (SECURITY_MODEL §5).

use std::io;

use crate::engine::Engine;
use crate::error::{AegisError, AegisResult, ErrorCode};
use crate::registry::ExitReason;

/// Starts an elevated copy with `launch` and, only once Windows has accepted
/// it, ends this copy. The order is the guarantee:
///
/// 1. Nothing is stopped, recorded or released before `launch` returns `Ok`.
///    A cancelled prompt (`ErrorKind::Interrupted`) or a failed launch leaves
///    this copy exactly as it was: it keeps the install claim and keeps
///    monitoring, and no quit record is written.
/// 2. On `Ok`, `engine.exit(Quit)` stops the MCP server and monitoring and
///    writes the quit record. Only then does `release_claim` let go of the
///    install. The elevated copy starts with `--after-restart` and waits for
///    that claim before it resumes anything, so the two copies never sample or
///    write history at the same time.
/// 3. `quit` ends this process (its exit handler finds nothing left to stop).
pub async fn restart_elevated(
    engine: &Engine,
    launch: impl FnOnce() -> io::Result<()>,
    release_claim: impl FnOnce(),
    quit: impl FnOnce(),
) -> AegisResult<()> {
    if engine.elevated() {
        return Err(AegisError::new(ErrorCode::Conflict, "AegisWin is already running as administrator."));
    }
    // Restarting would cut the running change off; waiting ones are cancelled when this copy exits.
    if let Some(tool) = engine.change_running() {
        return Err(AegisError::new(ErrorCode::Conflict, format!("Wait for {tool} to finish before restarting as administrator.")));
    }
    match launch() {
        Ok(()) => {
            engine.exit(ExitReason::Quit).await;
            release_claim();
            quit();
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::Interrupted => {
            Err(AegisError::new(ErrorCode::AccessDenied, "The administrator prompt was cancelled. AegisWin is still running as before."))
        }
        Err(e) => Err(AegisError::failed(format!("Could not restart as administrator: {e}"))),
    }
}
