//! One state-changing run at a time ([ADR 0003 §5.1](../../../documentation/adr/0003-action-plans.md)).
//!
//! Every run of a tool that can change the system waits here for the single
//! slot, first come first served by approval time. Read-only tools and dry
//! runs never come here. The slot is only a turn: nothing else is locked, so
//! there is nothing to deadlock on.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::Notify;

/// At most this many items wait; one more is refused before the PIN is checked.
pub const MAX_QUEUED: usize = 10;
/// An item still waiting this long after approval is dropped: the owner
/// approved it for the system as it was then.
pub const QUEUE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// AegisWin locked while the item waited.
    Locked,
    /// It waited longer than [`QUEUE_TIMEOUT`].
    Expired,
}

/// What the app shows in its "change in progress" bar.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChangeView {
    pub running: Option<String>,
    pub queued: usize,
}

struct Waiting {
    id: u64,
    label: String,
    ticket: Option<String>,
}

#[derive(Default)]
struct Inner {
    running: Option<(u64, String)>,
    queue: VecDeque<Waiting>,
    next_id: u64,
    /// Bumped by every lock; an item admitted in an older session is refused.
    epoch: u64,
    /// Idle auto-lock is due: let the running item finish, start nothing new.
    hold: bool,
}

#[derive(Default)]
pub struct Executor {
    inner: Mutex<Inner>,
    changed: Notify,
}

/// A place in the queue. Wait for it with [`Executor::turn`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Place(u64);

/// Holding this is holding the slot; dropping it lets the next item start.
pub struct Turn<'a> {
    executor: &'a Executor,
    id: u64,
}

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        let mut inner = self.executor.lock();
        if inner.running.as_ref().is_some_and(|(id, _)| *id == self.id) {
            inner.running = None;
        }
        drop(inner);
        self.executor.changed.notify_waiters();
    }
}

impl Executor {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Read before checking that the vault is unlocked, and pass to [`Self::enqueue`],
    /// so an item can never slip in across a lock.
    pub fn epoch(&self) -> u64 {
        self.lock().epoch
    }

    pub fn has_room(&self) -> bool {
        self.lock().queue.len() < MAX_QUEUED
    }

    /// Takes a place at the back. Fails when the queue is full, or when
    /// AegisWin locked since `epoch` was read.
    pub fn enqueue(&self, epoch: u64, label: &str, ticket: Option<&str>) -> Result<Place, Full> {
        let mut inner = self.lock();
        if inner.epoch != epoch {
            return Err(Full::Locked);
        }
        if inner.queue.len() >= MAX_QUEUED {
            return Err(Full::Full);
        }
        inner.next_id += 1;
        let id = inner.next_id;
        inner.queue.push_back(Waiting { id, label: label.to_owned(), ticket: ticket.map(str::to_owned) });
        Ok(Place(id))
    }

    /// Waits until `place` is at the front, nothing is running, and no
    /// auto-lock is pending, then takes the slot. If this future is dropped
    /// while waiting, the place is given up, so it cannot block the queue.
    pub async fn turn(&self, place: Place, deadline: Instant) -> Result<Turn<'_>, Stop> {
        struct GiveUp<'a>(&'a Executor, Place);
        impl Drop for GiveUp<'_> {
            fn drop(&mut self) {
                self.0.withdraw(self.1);
            }
        }
        let _give_up = GiveUp(self, place);
        let deadline = tokio::time::Instant::from_std(deadline);
        loop {
            // Registered before looking, so a change between the look and the wait is not missed.
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut inner = self.lock();
                let Some(index) = inner.queue.iter().position(|w| w.id == place.0) else {
                    return Err(Stop::Locked);
                };
                if index == 0 && inner.running.is_none() && !inner.hold {
                    let label = inner.queue.pop_front().map(|w| w.label).unwrap_or_default();
                    inner.running = Some((place.0, label));
                    return Ok(Turn { executor: self, id: place.0 });
                }
            }
            tokio::select! {
                () = &mut changed => {}
                () = tokio::time::sleep_until(deadline) => return Err(Stop::Expired),
            }
        }
    }

    /// Gives up a place. No-op once it has left the queue.
    pub fn withdraw(&self, place: Place) {
        let mut inner = self.lock();
        let before = inner.queue.len();
        inner.queue.retain(|w| w.id != place.0);
        let removed = inner.queue.len() != before;
        drop(inner);
        if removed {
            self.changed.notify_waiters();
        }
    }

    /// On lock: every waiting item is dropped and never resumes. A running
    /// item finishes; killing tools such as `sfc` mid-run is unsafe.
    pub fn cancel_all(&self) {
        let mut inner = self.lock();
        inner.epoch += 1;
        inner.hold = false;
        inner.queue.clear();
        drop(inner);
        self.changed.notify_waiters();
    }

    /// Gives up the place of an approval ticket, if it is waiting.
    pub fn withdraw_ticket(&self, ticket: &str) {
        let place = self.lock().queue.iter().find(|w| w.ticket.as_deref() == Some(ticket)).map(|w| Place(w.id));
        if let Some(place) = place {
            self.withdraw(place);
        }
    }

    /// True while idle auto-lock is waiting: a plan does not start its next step.
    pub fn held(&self) -> bool {
        self.lock().hold
    }

    /// While set, nothing new starts (idle auto-lock is waiting for the running item).
    pub fn hold(&self, on: bool) {
        let mut inner = self.lock();
        if inner.hold == on {
            return;
        }
        inner.hold = on;
        drop(inner);
        self.changed.notify_waiters();
    }

    /// True when `place` would start right now (nothing ahead, nothing running).
    pub fn is_next(&self, place: Place) -> bool {
        let inner = self.lock();
        inner.running.is_none() && !inner.hold && inner.queue.front().is_some_and(|w| w.id == place.0)
    }

    /// The tool running now, if any.
    pub fn running(&self) -> Option<String> {
        self.lock().running.as_ref().map(|(_, label)| label.clone())
    }

    /// 1-based place of an approval ticket in the queue.
    pub fn position(&self, ticket: &str) -> Option<usize> {
        self.lock().queue.iter().position(|w| w.ticket.as_deref() == Some(ticket)).map(|i| i + 1)
    }

    pub fn view(&self) -> ChangeView {
        let inner = self.lock();
        ChangeView { running: inner.running.as_ref().map(|(_, l)| l.clone()), queued: inner.queue.len() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Full {
    Full,
    Locked,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::{mpsc, oneshot};
    use tokio::task::JoinHandle;

    fn later() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    /// Waits for `place` on its own task; once it holds the slot it reports
    /// `name` and keeps the slot until the returned sender fires.
    fn waiter(ex: &Arc<Executor>, place: Place, name: &'static str, log: &mpsc::UnboundedSender<&'static str>) -> (JoinHandle<Result<(), Stop>>, oneshot::Sender<()>) {
        let (release, released) = oneshot::channel::<()>();
        let (ex, log) = (ex.clone(), log.clone());
        let task = tokio::spawn(async move {
            let turn = ex.turn(place, later()).await?;
            log.send(name).unwrap();
            let _ = released.await;
            drop(turn);
            Ok(())
        });
        (task, release)
    }

    async fn next(log: &mut mpsc::UnboundedReceiver<&'static str>) -> &'static str {
        tokio::time::timeout(Duration::from_secs(2), log.recv()).await.expect("an item should start").unwrap()
    }

    async fn nothing_starts(log: &mut mpsc::UnboundedReceiver<&'static str>) {
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(log.try_recv().is_err(), "nothing else may start");
    }

    #[tokio::test]
    async fn one_at_a_time_in_arrival_order() {
        let ex = Arc::new(Executor::default());
        let (tx, mut log) = mpsc::unbounded_channel();
        let e = ex.epoch();
        let a = ex.enqueue(e, "a", None).unwrap();
        let b = ex.enqueue(e, "b", Some("t-b")).unwrap();
        let c = ex.enqueue(e, "c", Some("t-c")).unwrap();
        assert_eq!((ex.position("t-b"), ex.position("t-c")), (Some(2), Some(3)));
        // Waiters start in queue order, not in the order they begin waiting.
        let (_tc, release_c) = waiter(&ex, c, "c", &tx);
        let (_tb, release_b) = waiter(&ex, b, "b", &tx);
        let (_ta, release_a) = waiter(&ex, a, "a", &tx);
        assert_eq!(next(&mut log).await, "a");
        assert_eq!(ex.view(), ChangeView { running: Some("a".into()), queued: 2 });
        assert_eq!(ex.position("t-b"), Some(1));
        nothing_starts(&mut log).await;
        release_a.send(()).unwrap();
        assert_eq!(next(&mut log).await, "b");
        assert_eq!(ex.running().as_deref(), Some("b"));
        nothing_starts(&mut log).await;
        release_b.send(()).unwrap();
        assert_eq!(next(&mut log).await, "c");
        release_c.send(()).unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(ex.view(), ChangeView::default());
    }

    #[tokio::test]
    async fn the_queue_is_capped() {
        let ex = Executor::default();
        let e = ex.epoch();
        for i in 0..MAX_QUEUED {
            ex.enqueue(e, &i.to_string(), None).unwrap();
        }
        assert!(!ex.has_room());
        assert_eq!(ex.enqueue(e, "one more", None), Err(Full::Full));
    }

    #[tokio::test]
    async fn lock_drops_waiters_and_older_admissions_but_not_the_running_item() {
        let ex = Arc::new(Executor::default());
        let (tx, mut log) = mpsc::unbounded_channel();
        let e = ex.epoch();
        let a = ex.enqueue(e, "a", None).unwrap();
        let b = ex.enqueue(e, "b", None).unwrap();
        let (_ta, release_a) = waiter(&ex, a, "a", &tx);
        assert_eq!(next(&mut log).await, "a");
        let (tb, _release_b) = waiter(&ex, b, "b", &tx);
        tokio::time::sleep(Duration::from_millis(20)).await;
        ex.cancel_all();
        assert_eq!(tokio::time::timeout(Duration::from_secs(2), tb).await.unwrap().unwrap(), Err(Stop::Locked));
        assert_eq!(ex.view(), ChangeView { running: Some("a".into()), queued: 0 });
        // Read before the lock, used after it: refused.
        assert_eq!(ex.enqueue(e, "late", None), Err(Full::Locked));
        // After unlock, new work still waits for the item that was running.
        let c = ex.enqueue(ex.epoch(), "c", None).unwrap();
        let (_tc, _release_c) = waiter(&ex, c, "c", &tx);
        nothing_starts(&mut log).await;
        release_a.send(()).unwrap();
        assert_eq!(next(&mut log).await, "c");
    }

    #[tokio::test]
    async fn hold_lets_the_running_item_finish_and_starts_nothing_new() {
        let ex = Arc::new(Executor::default());
        let (tx, mut log) = mpsc::unbounded_channel();
        let e = ex.epoch();
        let a = ex.enqueue(e, "a", None).unwrap();
        let b = ex.enqueue(e, "b", None).unwrap();
        let (_ta, release_a) = waiter(&ex, a, "a", &tx);
        let (_tb, _release_b) = waiter(&ex, b, "b", &tx);
        assert_eq!(next(&mut log).await, "a");
        ex.hold(true);
        release_a.send(()).unwrap();
        nothing_starts(&mut log).await;
        assert_eq!(ex.view(), ChangeView { running: None, queued: 1 });
        ex.hold(false);
        assert_eq!(next(&mut log).await, "b");
    }

    #[tokio::test]
    async fn an_item_waiting_too_long_expires_and_leaves_the_queue() {
        let ex = Executor::default();
        let e = ex.epoch();
        let a = ex.enqueue(e, "a", None).unwrap();
        let b = ex.enqueue(e, "b", Some("t")).unwrap();
        let _turn_a = ex.turn(a, later()).await.unwrap();
        assert_eq!(ex.turn(b, Instant::now() + Duration::from_millis(30)).await.err(), Some(Stop::Expired));
        assert_eq!(ex.position("t"), None);
        assert_eq!(ex.view().queued, 0);
    }

    #[tokio::test]
    async fn a_dropped_waiter_gives_up_its_place() {
        let ex = Arc::new(Executor::default());
        let (tx, mut log) = mpsc::unbounded_channel();
        let e = ex.epoch();
        let a = ex.enqueue(e, "a", None).unwrap();
        let b = ex.enqueue(e, "b", Some("t-b")).unwrap();
        let c = ex.enqueue(e, "c", None).unwrap();
        let (_ta, release_a) = waiter(&ex, a, "a", &tx);
        assert_eq!(next(&mut log).await, "a");
        // b's caller goes away while it waits (an agent disconnects).
        assert!(tokio::time::timeout(Duration::from_millis(30), ex.turn(b, later())).await.is_err());
        assert_eq!(ex.position("t-b"), None);
        let (_tc, _release_c) = waiter(&ex, c, "c", &tx);
        release_a.send(()).unwrap();
        assert_eq!(next(&mut log).await, "c");
    }
}
