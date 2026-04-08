//! Mock transport for testing.
//!
//! Provides a [`MockTransport`] that queues canned responses and records
//! sent messages, enabling test-driven development of higher layers
//! without needing a real SMB server.

use async_trait::async_trait;
use std::collections::VecDeque;
use std::sync::Mutex;

use crate::error::{Error, Result};
use crate::transport::{TransportReceive, TransportSend};

/// A mock transport that queues responses and records sent messages.
///
/// Use this in tests to simulate server conversations without a real
/// network connection. Responses are returned in FIFO order. When no
/// responses remain, `receive()` returns [`Error::Disconnected`].
///
/// Uses `std::sync::Mutex` (not `tokio::sync::Mutex`) because the
/// critical sections are trivially short (push/pop/clone) and never
/// hold the lock across an `.await` point.
pub struct MockTransport {
    /// Responses to return on `receive()`, in order.
    responses: Mutex<VecDeque<Vec<u8>>>,
    /// Messages that were sent, for assertions.
    sent: Mutex<Vec<Vec<u8>>>,
}

impl MockTransport {
    /// Create a new mock with no queued responses.
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(VecDeque::new()),
            sent: Mutex::new(Vec::new()),
        }
    }

    /// Queue a response to be returned by the next `receive()` call.
    pub fn queue_response(&self, data: Vec<u8>) {
        self.responses.lock().unwrap().push_back(data);
    }

    /// Queue multiple responses to be returned in order.
    pub fn queue_responses(&self, responses: Vec<Vec<u8>>) {
        let mut guard = self.responses.lock().unwrap();
        for r in responses {
            guard.push_back(r);
        }
    }

    /// Get all messages that were sent.
    pub fn sent_messages(&self) -> Vec<Vec<u8>> {
        self.sent.lock().unwrap().clone()
    }

    /// Get the nth sent message, or `None` if out of bounds.
    pub fn sent_message(&self, n: usize) -> Option<Vec<u8>> {
        self.sent.lock().unwrap().get(n).cloned()
    }

    /// How many messages have been sent.
    pub fn sent_count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }

    /// Clear all recorded sent messages.
    pub fn clear_sent(&self) {
        self.sent.lock().unwrap().clear();
    }
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TransportSend for MockTransport {
    async fn send(&self, data: &[u8]) -> Result<()> {
        self.sent.lock().unwrap().push(data.to_vec());
        Ok(())
    }
}

#[async_trait]
impl TransportReceive for MockTransport {
    async fn receive(&self) -> Result<Vec<u8>> {
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .ok_or(Error::Disconnected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn queue_response_and_receive_it() {
        let mock = MockTransport::new();
        let data = vec![0x01, 0x02, 0x03];
        mock.queue_response(data.clone());

        let received = mock.receive().await.unwrap();
        assert_eq!(received, data);
    }

    #[tokio::test]
    async fn queue_multiple_responses_received_in_order() {
        let mock = MockTransport::new();
        mock.queue_responses(vec![vec![0x01], vec![0x02, 0x03], vec![0x04, 0x05, 0x06]]);

        assert_eq!(mock.receive().await.unwrap(), vec![0x01]);
        assert_eq!(mock.receive().await.unwrap(), vec![0x02, 0x03]);
        assert_eq!(mock.receive().await.unwrap(), vec![0x04, 0x05, 0x06]);
    }

    #[tokio::test]
    async fn no_queued_responses_returns_disconnected() {
        let mock = MockTransport::new();

        let result = mock.receive().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, Error::Disconnected),
            "expected Disconnected, got: {err}"
        );
    }

    #[tokio::test]
    async fn send_records_message() {
        let mock = MockTransport::new();
        let msg = vec![0xAA, 0xBB, 0xCC];

        mock.send(&msg).await.unwrap();

        let sent = mock.sent_messages();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0], msg);
    }

    #[tokio::test]
    async fn sent_count_tracks_correctly() {
        let mock = MockTransport::new();
        assert_eq!(mock.sent_count(), 0);

        mock.send(&[0x01]).await.unwrap();
        assert_eq!(mock.sent_count(), 1);

        mock.send(&[0x02]).await.unwrap();
        assert_eq!(mock.sent_count(), 2);

        mock.send(&[0x03]).await.unwrap();
        assert_eq!(mock.sent_count(), 3);
    }

    #[tokio::test]
    async fn sent_message_returns_nth() {
        let mock = MockTransport::new();
        mock.send(&[0x0A]).await.unwrap();
        mock.send(&[0x0B]).await.unwrap();
        mock.send(&[0x0C]).await.unwrap();

        assert_eq!(mock.sent_message(0), Some(vec![0x0A]));
        assert_eq!(mock.sent_message(1), Some(vec![0x0B]));
        assert_eq!(mock.sent_message(2), Some(vec![0x0C]));
        assert_eq!(mock.sent_message(3), None);
    }

    #[tokio::test]
    async fn clear_sent_removes_all_recorded_messages() {
        let mock = MockTransport::new();
        mock.send(&[0x01]).await.unwrap();
        mock.send(&[0x02]).await.unwrap();
        assert_eq!(mock.sent_count(), 2);

        mock.clear_sent();
        assert_eq!(mock.sent_count(), 0);
        assert!(mock.sent_messages().is_empty());
    }

    #[tokio::test]
    async fn interleaved_send_and_receive() {
        let mock = MockTransport::new();
        mock.queue_responses(vec![vec![0xF1], vec![0xF2], vec![0xF3]]);

        // Send a request, receive a response, repeat.
        mock.send(&[0x01]).await.unwrap();
        assert_eq!(mock.receive().await.unwrap(), vec![0xF1]);

        mock.send(&[0x02]).await.unwrap();
        assert_eq!(mock.receive().await.unwrap(), vec![0xF2]);

        mock.send(&[0x03]).await.unwrap();
        assert_eq!(mock.receive().await.unwrap(), vec![0xF3]);

        // No more responses.
        assert!(mock.receive().await.is_err());

        // All three sends recorded.
        assert_eq!(mock.sent_count(), 3);
    }

    #[tokio::test]
    async fn concurrent_send_and_receive() {
        use std::sync::Arc;

        let mock = Arc::new(MockTransport::new());
        mock.queue_responses(vec![vec![0xAA]; 10]);

        let send_mock = Arc::clone(&mock);
        let send_task = tokio::spawn(async move {
            for i in 0..10u8 {
                send_mock.send(&[i]).await.unwrap();
            }
        });

        let recv_mock = Arc::clone(&mock);
        let recv_task = tokio::spawn(async move {
            let mut received = Vec::new();
            for _ in 0..10 {
                received.push(recv_mock.receive().await.unwrap());
            }
            received
        });

        send_task.await.unwrap();
        let received = recv_task.await.unwrap();

        assert_eq!(received.len(), 10);
        assert_eq!(mock.sent_count(), 10);
    }

    #[tokio::test]
    async fn empty_message_can_be_sent_and_received() {
        let mock = MockTransport::new();
        mock.queue_response(vec![]);

        mock.send(&[]).await.unwrap();
        let received = mock.receive().await.unwrap();

        assert!(received.is_empty());
        assert_eq!(mock.sent_message(0), Some(vec![]));
    }
}
