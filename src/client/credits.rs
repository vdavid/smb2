//! Connection-wide SMB2 credit accounting.
//!
//! A server hands the client a budget ("credits") and every request spends
//! from it: `CreditCharge = ceil(max(SendPayload, ExpectedResponse) / 65536)`,
//! at least 1 (MS-SMB2 § 3.1.5.2). Responses carry a `CreditResponse` grant
//! that puts credits back. A client that sends more than it holds is in
//! violation, and MS-SMB2 § 3.3.1.1 lets the server drop the connection —
//! some servers instead stop answering while the TCP socket stays open, which
//! looks exactly like a hung client.
//!
//! The budget is per *connection*, so it lives here rather than in any one
//! stream: several pipelined transfers over one connection draw on the same
//! pool.
//!
//! **Credits are spent on send, not on receipt.** That is the whole point of
//! this type. Accounting for a request only once its answer arrives leaves
//! everything currently in flight invisible, and concurrent senders each read
//! the same "plenty available" number and pile on.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{AcquireError, Semaphore};

/// The window the client steers the server toward, in credits.
///
/// Every request asks for its own charge back plus whatever is needed to reach
/// this number, so an idle connection asks for little and a saturated one asks
/// for a lot. 512 credits is comfortably more than the deepest pipeline this
/// crate opens (32 requests at 8 credits each for 512 KB chunks), leaving room
/// for other work on the same connection. Servers clamp the request to their
/// own maximum, so asking high is safe; asking low is not, because a window
/// that shrinks to nothing serializes every transfer.
const CREDIT_TARGET: u16 = 512;

/// Default bound on how long a send waits for the server to grant credits
/// before giving up with [`Error::CreditStarvation`](crate::Error::CreditStarvation).
///
/// Long enough that a merely busy server is never mistaken for a dead one,
/// short enough that a silent one surfaces as an error instead of a hang.
pub(crate) const DEFAULT_CREDIT_WAIT: Duration = Duration::from_secs(30);

/// Server-granted credits that have not been spent yet.
///
/// One `Semaphore` permit per unspent credit. Taking permits is the gate: a
/// request acquires its `CreditCharge` worth *before* its bytes reach the
/// wire, and only a grant on a response puts them back. Waiting is bounded by
/// the caller (see `Inner::reserve_credits`), so a server that stops granting
/// produces an error rather than a wait that never ends.
pub(crate) struct CreditPool {
    /// The live budget. Behind a `Mutex<Arc<..>>` rather than owned outright
    /// because a closed `Semaphore` can never reopen (tokio makes closing
    /// terminal), and a connection revived in place needs a budget again.
    /// [`reset`](Self::reset) swaps in a fresh one; whoever still holds the old
    /// `Arc` is parked on a generation that is never coming back and sees
    /// `Err` from the close that killed it.
    permits: Mutex<Arc<Semaphore>>,
    /// The reserve deadline in milliseconds, tunable per connection.
    wait_ms: AtomicU64,
}

impl CreditPool {
    /// A fresh pool holds the single credit a client has before NEGOTIATE
    /// (MS-SMB2 § 3.2.5.1.1) — enough to send NEGOTIATE and nothing else.
    pub(crate) fn new() -> Self {
        Self {
            permits: Mutex::new(Arc::new(Semaphore::new(1))),
            wait_ms: AtomicU64::new(DEFAULT_CREDIT_WAIT.as_millis() as u64),
        }
    }

    /// The budget as of right now.
    fn current(&self) -> Arc<Semaphore> {
        Arc::clone(&self.permits.lock().unwrap())
    }

    /// Throw the spent budget away and start again from the pre-NEGOTIATE
    /// single credit.
    ///
    /// Called when a connection is revived on a new transport. ❌ Don't reuse
    /// the old budget: its permits were granted by a session that no longer
    /// exists, and the new server may have a much smaller window. Carrying
    /// them over would let the first burst after a reconnect out-spend the
    /// server exactly the way the original wedge did.
    pub(crate) fn reset(&self) {
        *self.permits.lock().unwrap() = Arc::new(Semaphore::new(1));
    }

    /// Credits on hand: granted by the server and not reserved by a request.
    ///
    /// Saturates at `u16::MAX`; no server grants a window that wide.
    pub(crate) fn available(&self) -> u16 {
        self.current().available_permits().min(u16::MAX as usize) as u16
    }

    /// Bank the `CreditResponse` from a response header.
    pub(crate) fn grant(&self, credits: u16) {
        if credits > 0 {
            self.current().add_permits(credits as usize);
        }
    }

    /// Take `charge` credits if they are on hand right now.
    pub(crate) fn try_reserve(&self, charge: u16) -> Option<CreditReservation> {
        let permits = self.current();
        match permits.clone().try_acquire_many_owned(u32::from(charge)) {
            Ok(permit) => {
                permit.forget();
                Some(CreditReservation::new(permits, charge))
            }
            Err(_) => None,
        }
    }

    /// Wait for `charge` credits. Resolves once they are reserved, or with
    /// `Err` if the pool was closed by a connection teardown.
    ///
    /// Fair: waiters are served in order, so a large request can't be starved
    /// by a stream of small ones behind it.
    ///
    /// Binds to the budget as it is when the wait starts, so a reset mid-wait
    /// resolves the waiter with `Err` (the pool it was queued on was closed)
    /// rather than silently migrating it onto the new session's budget.
    pub(crate) async fn reserve(&self, charge: u16) -> Result<CreditReservation, AcquireError> {
        let permits = self.current();
        permits
            .clone()
            .acquire_many_owned(u32::from(charge))
            .await?
            .forget();
        Ok(CreditReservation::new(permits, charge))
    }

    /// How many credits to request on a request charging `charge`.
    ///
    /// Always at least the charge, so the window can't shrink under a steady
    /// load, plus enough to climb back to [`CREDIT_TARGET`].
    pub(crate) fn request_for(&self, charge: u16) -> u16 {
        charge.saturating_add(CREDIT_TARGET.saturating_sub(self.available()))
    }

    /// How long [`Inner::reserve_credits`](crate::client::connection) waits
    /// before declaring starvation.
    pub(crate) fn wait_timeout(&self) -> Duration {
        Duration::from_millis(self.wait_ms.load(Ordering::Relaxed))
    }

    /// Retune the starvation deadline.
    pub(crate) fn set_wait_timeout(&self, after: Duration) {
        let ms = u64::try_from(after.as_millis()).unwrap_or(u64::MAX);
        self.wait_ms.store(ms, Ordering::Relaxed);
    }

    /// Wake every waiter with an error. Called when the connection dies, so a
    /// task parked on credits fails immediately instead of waiting out the
    /// full deadline for a server that will never answer again.
    pub(crate) fn close(&self) {
        self.current().close();
    }

    /// Whether [`close`](Self::close) has been called.
    pub(crate) fn is_closed(&self) -> bool {
        self.current().is_closed()
    }

    /// Force the pool to exactly `credits`, for tests that need to stage a
    /// specific window without a full negotiate exchange.
    #[cfg(test)]
    pub(crate) fn set_available(&self, credits: u16) {
        let permits = self.current();
        let have = permits.available_permits();
        let want = usize::from(credits);
        match want.cmp(&have) {
            std::cmp::Ordering::Greater => permits.add_permits(want - have),
            std::cmp::Ordering::Less => {
                if let Ok(permit) = permits.try_acquire_many((have - want) as u32) {
                    permit.forget();
                }
            }
            std::cmp::Ordering::Equal => {}
        }
    }
}

/// Credits taken from the pool for one request that has not been sent yet.
///
/// Dropping without [`commit`](Self::commit) refunds them — that is the path
/// for a request that failed to sign, encrypt, or reach the transport, and for
/// a caller whose future is dropped before the send.
#[must_use = "dropping the reservation refunds the credits without sending"]
pub(crate) struct CreditReservation {
    permits: Option<Arc<Semaphore>>,
    charge: u16,
}

impl CreditReservation {
    fn new(permits: Arc<Semaphore>, charge: u16) -> Self {
        Self {
            permits: Some(permits),
            charge,
        }
    }

    /// The bytes are on the wire: the credits belong to the server now.
    pub(crate) fn commit(mut self) {
        self.permits = None;
    }
}

impl Drop for CreditReservation {
    fn drop(&mut self) {
        if let Some(permits) = &self.permits {
            permits.add_permits(self.charge as usize);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reservation_holds_credits_out_of_the_pool_until_it_is_refunded() {
        let pool = CreditPool::new();
        pool.set_available(10);

        let reservation = pool.try_reserve(4).unwrap();
        assert_eq!(pool.available(), 6);

        drop(reservation);
        assert_eq!(
            pool.available(),
            10,
            "an unsent request gives its credits back"
        );
    }

    #[test]
    fn a_committed_reservation_leaves_the_credits_with_the_server() {
        let pool = CreditPool::new();
        pool.set_available(10);

        pool.try_reserve(4).unwrap().commit();

        assert_eq!(
            pool.available(),
            6,
            "credits spent on the wire only come back as a grant"
        );
    }

    #[test]
    fn a_charge_larger_than_the_window_is_not_partially_reserved() {
        let pool = CreditPool::new();
        pool.set_available(3);

        assert!(pool.try_reserve(4).is_none());
        assert_eq!(pool.available(), 3, "a failed reserve takes nothing");
    }

    #[test]
    fn the_credit_request_always_covers_the_charge_and_climbs_to_the_target() {
        let pool = CreditPool::new();

        pool.set_available(0);
        assert_eq!(pool.request_for(8), 8 + CREDIT_TARGET);

        pool.set_available(CREDIT_TARGET);
        assert_eq!(
            pool.request_for(8),
            8,
            "at target, ask only for the charge back"
        );

        pool.set_available(u16::MAX);
        assert_eq!(pool.request_for(8), 8, "never ask for less than the charge");
    }

    #[tokio::test]
    async fn a_grant_wakes_a_waiter() {
        let pool = CreditPool::new();
        pool.set_available(0);

        let waiting = pool.reserve(4);
        tokio::pin!(waiting);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut waiting)
                .await
                .is_err(),
            "nothing to reserve yet"
        );

        pool.grant(4);
        waiting
            .await
            .expect("the grant satisfies the waiter")
            .commit();
        assert_eq!(pool.available(), 0);
    }

    #[tokio::test]
    async fn closing_the_pool_fails_waiters_instead_of_parking_them() {
        let pool = CreditPool::new();
        pool.set_available(0);

        let waiting = pool.reserve(1);
        tokio::pin!(waiting);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut waiting)
                .await
                .is_err()
        );

        pool.close();
        assert!(waiting.await.is_err());
        assert!(pool.is_closed());
    }

    #[tokio::test]
    async fn a_reset_pool_starts_from_one_credit_again_and_is_no_longer_closed() {
        let pool = CreditPool::new();
        pool.set_available(400);
        pool.close();
        assert!(pool.is_closed());

        pool.reset();

        assert!(
            !pool.is_closed(),
            "a revived connection needs a live budget"
        );
        assert_eq!(
            pool.available(),
            1,
            "credits granted by a dead session must not carry over -- the new \
             server's window may be far smaller"
        );
        pool.try_reserve(1).unwrap().commit();
    }

    #[tokio::test]
    async fn a_waiter_on_the_old_budget_is_failed_by_the_reset_rather_than_migrated() {
        let pool = CreditPool::new();
        pool.set_available(0);

        let waiting = pool.reserve(4);
        tokio::pin!(waiting);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut waiting)
                .await
                .is_err(),
            "nothing to reserve yet"
        );

        // Teardown, then revival. The waiter belongs to the dead generation.
        pool.close();
        pool.reset();
        pool.grant(64);

        assert!(
            tokio::time::timeout(Duration::from_millis(200), waiting)
                .await
                .expect("the waiter must resolve, not hang")
                .is_err(),
            "a send queued against the old session must fail rather than \
             silently continue on the new one"
        );
    }

    #[test]
    fn an_old_reservation_never_refunds_the_new_generation() {
        let pool = CreditPool::new();
        let reservation = pool.try_reserve(1).unwrap();
        assert_eq!(pool.available(), 0);

        pool.close();
        pool.reset();
        assert_eq!(pool.available(), 1);
        drop(reservation);

        assert_eq!(
            pool.available(),
            1,
            "an old session's refund must stay in its retired credit pool"
        );
    }
}
