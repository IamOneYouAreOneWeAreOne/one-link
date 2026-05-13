//! Routing context: who / when / what the message is.
//!
//! The context is hashed into a 32-byte key that indexes the
//! posterior table. The hash captures the discrete-bucketed
//! features (hour-of-day, day-of-week, message class) plus the
//! 32-byte contact pin so different contacts get separate
//! posteriors.

use blake3::Hasher;

/// Domain-separation tag for the routing-context hash.
pub const ROUTING_CONTEXT_DOMAIN: &[u8] = b"OL-mesh-routing-context-v1";

/// One discrete routing context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoutingContext {
    /// 32-byte BLAKE3 pin of the contact's master verifying key
    /// (the friend the message is from). Zero bytes for system
    /// messages with no contact.
    pub contact_pin: [u8; 32],
    /// Hour-of-day bucket (0..23).
    pub hour_bucket: u8,
    /// Day-of-week bucket (0..6, Monday = 0).
    pub day_of_week: u8,
    /// 4-byte message-class tag (e.g. `b"DM  "`, `b"FILE"`,
    /// `b"CALL"`). Anything the daemon wants to bucket on.
    pub message_class: [u8; 4],
    /// Urgency bucket (0..3, higher = more urgent).
    pub urgency: u8,
}

impl RoutingContext {
    /// Compute the 32-byte canonical hash that indexes the
    /// posterior table.
    #[must_use]
    pub fn canonical_hash(&self) -> [u8; 32] {
        let mut h = Hasher::new();
        h.update(ROUTING_CONTEXT_DOMAIN);
        h.update(&self.contact_pin);
        h.update(&[self.hour_bucket, self.day_of_week]);
        h.update(&self.message_class);
        h.update(&[self.urgency]);
        *h.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(contact: u8, hour: u8, dow: u8, class: [u8; 4], urg: u8) -> RoutingContext {
        RoutingContext {
            contact_pin: [contact; 32],
            hour_bucket: hour,
            day_of_week: dow,
            message_class: class,
            urgency: urg,
        }
    }

    #[test]
    fn hash_deterministic() {
        let c = ctx(1, 14, 2, *b"DM  ", 1);
        assert_eq!(c.canonical_hash(), c.canonical_hash());
    }

    #[test]
    fn different_contacts_distinct_hashes() {
        let a = ctx(1, 14, 2, *b"DM  ", 1);
        let b = ctx(2, 14, 2, *b"DM  ", 1);
        assert_ne!(a.canonical_hash(), b.canonical_hash());
    }

    #[test]
    fn different_hours_distinct_hashes() {
        let a = ctx(1, 9, 2, *b"DM  ", 1);
        let b = ctx(1, 21, 2, *b"DM  ", 1);
        assert_ne!(a.canonical_hash(), b.canonical_hash());
    }

    #[test]
    fn different_classes_distinct_hashes() {
        let a = ctx(1, 14, 2, *b"DM  ", 1);
        let b = ctx(1, 14, 2, *b"FILE", 1);
        assert_ne!(a.canonical_hash(), b.canonical_hash());
    }
}
