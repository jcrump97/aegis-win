//! Restart as administrator, with the launch, the install claim and the quit
//! passed in so every path can be tested without a UAC prompt (SECURITY_MODEL §5).

use std::future::Future;
use std::io;
use std::time::Duration;

use crate::engine::Engine;
use crate::error::{AegisError, AegisResult, ErrorCode};
use crate::registry::ExitReason;

/// How long the elevated copy (`--after-restart`) waits for the install claim
/// before it gives up and acts as an ordinary second launch.
pub const AFTER_RESTART_WAIT: Duration = Duration::from_secs(30);

/// How long this copy may spend stopping before it lets go of the claim
/// anyway, so the elevated copy, which is already waiting, always gets it
/// in time (issue #91).
pub const EXIT_BUDGET: Duration = Duration::from_secs(20);

/// Starts an elevated copy with `launch` and, only once Windows has accepted
/// it, ends this copy. The order is the guarantee:
///
/// 1. Nothing is stopped, recorded or released before `launch` returns `Ok`.
///    A cancelled prompt (`ErrorKind::Interrupted`) or a failed launch leaves
///    this copy exactly as it was: it keeps the install claim and keeps
///    monitoring, and no quit record is written. While the prompt is open no
///    change starts (one approved meanwhile waits, and is cancelled by the
///    exit if the launch is accepted), so the exit cannot cut a change off.
/// 2. On `Ok`, `engine.exit(Quit)` stops the MCP server and monitoring and
///    writes the quit record, within [`EXIT_BUDGET`]. Only then does
///    `release_claim` let go of the install. The elevated copy starts with
///    `--after-restart` and waits for that claim before it resumes anything,
///    so the two copies never sample or write history at the same time.
/// 3. `quit` ends this process (its exit handler finds nothing left to stop).
///
/// After an accepted launch, `release_claim` and `quit` run even if the exit
/// panics or runs past its budget, so this copy never stays half-stopped
/// with the claim held while the elevated copy waits for it. If the elevated
/// copy dies before it takes the claim, no copy is left running; the owner
/// starts AegisWin again.
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
    let _hold = engine
        .hold_changes_for_restart()
        .map_err(|tool| AegisError::new(ErrorCode::Conflict, format!("Wait for {tool} to finish before restarting as administrator.")))?;
    match launch() {
        Ok(()) => {
            finish(engine.exit(ExitReason::Quit), EXIT_BUDGET, release_claim, quit).await;
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::Interrupted => {
            Err(AegisError::new(ErrorCode::AccessDenied, "The administrator prompt was cancelled. AegisWin is still running as before."))
        }
        Err(e) => Err(AegisError::failed(format!("Could not restart as administrator: {e}"))),
    }
}

/// Runs `exit` for at most `budget`, then `release_claim`, then `quit`. The
/// last two also run when `exit` panics or this future is dropped.
async fn finish(exit: impl Future<Output = ()>, budget: Duration, release_claim: impl FnOnce(), quit: impl FnOnce()) {
    struct Finish<R: FnOnce(), Q: FnOnce()>(Option<R>, Option<Q>);
    impl<R: FnOnce(), Q: FnOnce()> Drop for Finish<R, Q> {
        fn drop(&mut self) {
            if let Some(release) = self.0.take() {
                release();
            }
            if let Some(quit) = self.1.take() {
                quit();
            }
        }
    }
    let finish = Finish(Some(release_claim), Some(quit));
    // Past the budget the rest of the stop is dropped: the process ends anyway.
    let _ = tokio::time::timeout(budget, exit).await;
    drop(finish);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    type Steps = Arc<Mutex<Vec<&'static str>>>;

    fn steps() -> (Steps, impl FnOnce() + Send + 'static, impl FnOnce() + Send + 'static) {
        let log: Steps = Arc::default();
        let (a, b) = (log.clone(), log.clone());
        (log, move || a.lock().unwrap().push("release"), move || b.lock().unwrap().push("quit"))
    }

    #[test]
    fn the_budget_ends_before_the_elevated_copy_stops_waiting() {
        assert!(EXIT_BUDGET + Duration::from_secs(5) <= AFTER_RESTART_WAIT);
    }

    #[tokio::test]
    async fn a_normal_exit_releases_then_quits_after_it() {
        let (log, release, quit) = steps();
        let exited = log.clone();
        finish(async move { exited.lock().unwrap().push("exit") }, EXIT_BUDGET, release, quit).await;
        assert_eq!(*log.lock().unwrap(), ["exit", "release", "quit"]);
    }

    #[tokio::test(start_paused = true)]
    async fn an_exit_that_runs_past_its_budget_still_releases_and_quits_in_time() {
        let (log, release, quit) = steps();
        let started = tokio::time::Instant::now();
        finish(std::future::pending::<()>(), EXIT_BUDGET, release, quit).await;
        assert!(started.elapsed() >= EXIT_BUDGET && started.elapsed() < AFTER_RESTART_WAIT);
        assert_eq!(*log.lock().unwrap(), ["release", "quit"]);
    }

    #[tokio::test]
    async fn an_exit_that_panics_still_releases_and_quits() {
        let (log, release, quit) = steps();
        let task = tokio::spawn(finish(async { panic!("exit failed") }, EXIT_BUDGET, release, quit));
        assert!(task.await.unwrap_err().is_panic());
        assert_eq!(*log.lock().unwrap(), ["release", "quit"]);
    }
}
