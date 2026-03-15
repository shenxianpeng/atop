use std::collections::VecDeque;

/// Generic ring buffer with a default capacity of 60 (60 frames ≈ 1 minute @1 fps).
/// See SPEC.md Storage subsystem design (implemented in P2, consumed in the PV phase).
#[allow(dead_code)]
pub struct RingBuffer<T> {
    capacity: usize,
    buf: VecDeque<(u64, T)>,
    next_id: u64,
}

impl<T> RingBuffer<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            buf: VecDeque::with_capacity(capacity),
            next_id: 1,
        }
    }

    /// Write a frame and return its assigned snapshot_id (monotonically increasing)
    pub fn push(&mut self, item: T) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        if self.buf.len() >= self.capacity {
            self.buf.pop_front();
        }
        self.buf.push_back((id, item));
        id
    }

    /// Look up a historical frame by snapshot_id (returns None if it has been evicted)
    pub fn rollback_to(&self, id: u64) -> Option<&T> {
        self.buf.iter().find(|(sid, _)| *sid == id).map(|(_, item)| item)
    }

    pub fn latest(&self) -> Option<&T> {
        self.buf.back().map(|(_, item)| item)
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_and_latest() {
        let mut rb: RingBuffer<i32> = RingBuffer::new(3);
        let id1 = rb.push(10);
        let id2 = rb.push(20);
        assert_eq!(rb.latest(), Some(&20));
        assert_eq!(rb.rollback_to(id1), Some(&10));
        assert_eq!(rb.rollback_to(id2), Some(&20));
    }

    #[test]
    fn capacity_evicts_oldest() {
        let mut rb: RingBuffer<i32> = RingBuffer::new(2);
        let id1 = rb.push(1);
        rb.push(2);
        rb.push(3);
        assert_eq!(rb.len(), 2);
        assert_eq!(rb.rollback_to(id1), None); // evicted
        assert_eq!(rb.latest(), Some(&3));
    }

    #[test]
    fn ids_are_monotonically_increasing() {
        let mut rb: RingBuffer<&str> = RingBuffer::new(10);
        let a = rb.push("a");
        let b = rb.push("b");
        let c = rb.push("c");
        assert!(a < b && b < c);
    }

    #[test]
    fn capacity_one_works() {
        let mut rb: RingBuffer<u64> = RingBuffer::new(1);
        rb.push(99);
        let id = rb.push(100);
        assert_eq!(rb.len(), 1);
        assert_eq!(rb.rollback_to(id), Some(&100));
    }
}
