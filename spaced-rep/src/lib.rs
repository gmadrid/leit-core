use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const NUM_BOXES: u8 = 9;

/// Interval in seconds for each box level.
const INTERVALS: [u64; NUM_BOXES as usize] = [
    20,      // Box 0: 20 seconds
    60,      // Box 1: 1 minute
    300,     // Box 2: 5 minutes
    1_800,   // Box 3: 30 minutes
    7_200,   // Box 4: 2 hours
    21_600,  // Box 5: 6 hours
    86_400,  // Box 6: 1 day
    259_200, // Box 7: 3 days
    604_800, // Box 8: 1 week
];

/// Human-readable labels for each box interval.
pub const BOX_LABELS: [&str; NUM_BOXES as usize] =
    ["20s", "1m", "5m", "30m", "2h", "6h", "1d", "3d", "1w"];

#[cfg(not(target_arch = "wasm32"))]
fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(target_arch = "wasm32")]
fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// Summary of deck state relative to a candidate pool.
#[derive(Debug, Clone, Default)]
pub struct DeckSummary {
    pub unasked: u32,
    pub weak: u32,
    pub learning: u32,
    pub mastered: u32,
    pub due: u32,
}

/// Per-item tracking data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ItemData {
    pub box_level: u8,
    pub last_reviewed: u64,
    pub times_correct: u32,
    pub times_wrong: u32,
}

impl ItemData {
    fn interval(&self) -> u64 {
        INTERVALS[self.box_level as usize]
    }

    fn is_due(&self, now: u64) -> bool {
        now.saturating_sub(self.last_reviewed) >= self.interval()
    }

    fn promote(&mut self, now: u64) {
        self.box_level = (self.box_level + 1).min(NUM_BOXES - 1);
        self.last_reviewed = now;
        self.times_correct += 1;
    }

    fn demote(&mut self, now: u64) {
        self.box_level = 0;
        self.last_reviewed = now;
        self.times_wrong += 1;
    }
}

/// A generic spaced repetition deck.
///
/// Tracks items by string key. Knows nothing about the domain —
/// the caller maps domain objects to/from keys.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Deck {
    items: HashMap<String, ItemData>,
    #[serde(skip)]
    last_key: Option<String>,
}

impl Deck {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an answer for the given key.
    /// Correct answers promote the item only if it is due (to prevent
    /// rapid advancement from repeated random encounters).
    /// Wrong answers always demote to box 0.
    pub fn record(&mut self, key: &str, correct: bool) {
        let now = now_secs();
        self.last_key = Some(key.to_string());
        let item = self.items.entry(key.to_string()).or_default();
        if correct {
            if item.is_due(now) {
                item.promote(now);
            } else {
                item.times_correct += 1;
            }
        } else {
            item.demote(now);
        }
    }

    /// Look up tracking data for a key.
    pub fn get(&self, key: &str) -> Option<&ItemData> {
        self.items.get(key)
    }

    /// Pick the next item to review from the given candidates.
    ///
    /// Priority:
    /// 1. Due items, lowest box first (weakest due items first)
    /// 2. If nothing is due, the item with the lowest box level
    /// 3. Unseen items (not yet in the deck)
    ///
    /// Returns `None` only if `candidates` is empty.
    pub fn next_item<'a>(&self, candidates: &'a [String]) -> Option<&'a str> {
        if candidates.is_empty() {
            return None;
        }

        let now = now_secs();

        // Separate into seen and unseen
        let mut due: Vec<(&str, &ItemData)> = Vec::new();
        let mut not_due: Vec<(&str, &ItemData)> = Vec::new();
        let mut unseen: Vec<&str> = Vec::new();

        let skip = self.last_key.as_deref();
        for key in candidates {
            if Some(key.as_str()) == skip {
                continue;
            }
            match self.items.get(key.as_str()) {
                Some(item) if item.is_due(now) => due.push((key.as_str(), item)),
                Some(item) => not_due.push((key.as_str(), item)),
                None => unseen.push(key.as_str()),
            }
        }

        let mut rng = thread_rng();

        // 1. Due items, random among lowest box level
        if !due.is_empty() {
            let min_box = due.iter().map(|(_, item)| item.box_level).min().unwrap();
            let lowest: Vec<_> = due
                .iter()
                .filter(|(_, item)| item.box_level == min_box)
                .collect();
            return Some(lowest[rng.gen_range(0..lowest.len())].0);
        }

        // 2. Unseen items, random pick
        if !unseen.is_empty() {
            return Some(unseen[rng.gen_range(0..unseen.len())]);
        }

        // 3. Random among lowest box not-due items
        if !not_due.is_empty() {
            let min_box = not_due
                .iter()
                .map(|(_, item)| item.box_level)
                .min()
                .unwrap();
            let lowest: Vec<_> = not_due
                .iter()
                .filter(|(_, item)| item.box_level == min_box)
                .collect();
            return Some(lowest[rng.gen_range(0..lowest.len())].0);
        }

        None
    }

    /// Return all candidate keys that are currently due for review.
    pub fn due_items<'a>(&self, candidates: &'a [String]) -> Vec<&'a str> {
        let now = now_secs();
        candidates
            .iter()
            .filter(|key| match self.items.get(key.as_str()) {
                Some(item) => item.is_due(now),
                None => true, // unseen items are always due
            })
            .map(|k| k.as_str())
            .collect()
    }

    /// Count of items at each box level for the given candidates.
    /// Index = box level, value = count. Unseen items are not counted.
    pub fn box_counts(&self, candidates: &[String]) -> [u32; NUM_BOXES as usize] {
        let mut counts = [0u32; NUM_BOXES as usize];
        for key in candidates {
            if let Some(item) = self.items.get(key.as_str()) {
                counts[item.box_level as usize] += 1;
            }
        }
        counts
    }

    /// Per-box count of items that are currently due for review.
    pub fn box_due_counts(&self, candidates: &[String]) -> [u32; NUM_BOXES as usize] {
        let now = now_secs();
        let mut counts = [0u32; NUM_BOXES as usize];
        for key in candidates {
            if let Some(item) = self.items.get(key.as_str()) {
                if item.is_due(now) {
                    counts[item.box_level as usize] += 1;
                }
            }
        }
        counts
    }

    /// Number of candidates not yet seen.
    pub fn unseen_count(&self, candidates: &[String]) -> u32 {
        candidates
            .iter()
            .filter(|k| !self.items.contains_key(k.as_str()))
            .count() as u32
    }

    /// Summary of item states relative to a set of candidates.
    pub fn summary(&self, candidates: &[String]) -> DeckSummary {
        let now = now_secs();
        let mut unasked = 0u32;
        let mut weak = 0u32;
        let mut learning = 0u32;
        let mut mastered = 0u32;
        let mut due = 0u32;

        for key in candidates {
            match self.items.get(key.as_str()) {
                None => {
                    unasked += 1;
                    due += 1; // unseen items are always due
                }
                Some(item) => {
                    match item.box_level {
                        0..=3 => weak += 1,
                        4..=6 => learning += 1,
                        _ => mastered += 1, // box 7-8
                    }
                    if item.is_due(now) {
                        due += 1;
                    }
                }
            }
        }

        DeckSummary {
            unasked,
            weak,
            learning,
            mastered,
            due,
        }
    }

    /// Seconds until the next candidate becomes due, or `None` if any are already due/unseen.
    pub fn next_due_in(&self, candidates: &[String]) -> Option<u64> {
        let now = now_secs();
        let mut earliest: Option<u64> = None;

        for key in candidates {
            match self.items.get(key.as_str()) {
                None => return None, // unseen item is immediately due
                Some(item) => {
                    if item.is_due(now) {
                        return None; // already due
                    }
                    let due_at = item.last_reviewed + item.interval();
                    let wait = due_at.saturating_sub(now);
                    earliest = Some(match earliest {
                        Some(e) => e.min(wait),
                        None => wait,
                    });
                }
            }
        }

        earliest
    }

    /// Number of items being tracked.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_deck_is_empty() {
        let deck = Deck::new();
        assert!(deck.is_empty());
        assert_eq!(deck.len(), 0);
    }

    #[test]
    fn test_record_creates_item() {
        let mut deck = Deck::new();
        deck.record("item1", true);
        assert_eq!(deck.len(), 1);
        let item = deck.get("item1").unwrap();
        assert_eq!(item.times_correct, 1);
        assert_eq!(item.times_wrong, 0);
        assert_eq!(item.box_level, 1);
    }

    /// Helper: make an item due by backdating its last_reviewed.
    fn make_due(deck: &mut Deck, key: &str) {
        if let Some(item) = deck.items.get_mut(key) {
            item.last_reviewed = 0;
        }
    }

    #[test]
    fn test_wrong_answer_demotes_to_box_0() {
        let mut deck = Deck::new();
        deck.record("item1", true);
        make_due(&mut deck, "item1");
        deck.record("item1", true);
        assert_eq!(deck.get("item1").unwrap().box_level, 2);
        deck.record("item1", false);
        assert_eq!(deck.get("item1").unwrap().box_level, 0);
        assert_eq!(deck.get("item1").unwrap().times_wrong, 1);
    }

    #[test]
    fn test_box_level_caps_at_max() {
        let mut deck = Deck::new();
        for _ in 0..20 {
            make_due(&mut deck, "item1");
            deck.record("item1", true);
        }
        assert_eq!(deck.get("item1").unwrap().box_level, NUM_BOXES - 1);
    }

    #[test]
    fn test_correct_answer_not_due_does_not_promote() {
        let mut deck = Deck::new();
        deck.record("item1", true); // box 0 -> 1
        assert_eq!(deck.get("item1").unwrap().box_level, 1);

        // Answer correctly again immediately (not due yet)
        deck.record("item1", true);
        // Should NOT promote — still box 1
        assert_eq!(deck.get("item1").unwrap().box_level, 1);
        // But times_correct should still increment
        assert_eq!(deck.get("item1").unwrap().times_correct, 2);
    }

    #[test]
    fn test_next_item_prefers_unseen() {
        let mut deck = Deck::new();
        // Record item1 as correct (promotes to box 1, not due for 60s)
        deck.record("item1", true);

        let candidates = vec!["item1".to_string(), "item2".to_string()];
        let next = deck.next_item(&candidates).unwrap();
        // item2 is unseen, so it should be preferred after due items
        // item1 at box 1 is not due yet, item2 is unseen (due)
        assert_eq!(next, "item2");
    }

    #[test]
    fn test_next_item_prefers_due_over_unseen() {
        let mut deck = Deck::new();
        // Record item1 as wrong (box 0), then backdate so it's due
        deck.record("item1", false);
        deck.items.get_mut("item1").unwrap().last_reviewed = 0;
        // Record item3 so item1 is no longer the last key
        deck.record("item3", true);

        let candidates = vec!["item1".to_string(), "item2".to_string()];
        let next = deck.next_item(&candidates).unwrap();
        // item1 is due (box 0, backdated), item2 is unseen (also due), but item1 has lower box
        assert_eq!(next, "item1");
    }

    #[test]
    fn test_next_item_skips_last_asked() {
        let mut deck = Deck::new();
        deck.record("item1", false); // item1 is last key, box 0

        let candidates = vec!["item1".to_string(), "item2".to_string()];
        let next = deck.next_item(&candidates).unwrap();
        // item1 is skipped because it was just asked; item2 is unseen
        assert_eq!(next, "item2");
    }

    #[test]
    fn test_next_item_empty_candidates() {
        let deck = Deck::new();
        assert!(deck.next_item(&[]).is_none());
    }

    #[test]
    fn test_due_items_includes_unseen() {
        let deck = Deck::new();
        let candidates = vec!["a".to_string(), "b".to_string()];
        let due = deck.due_items(&candidates);
        assert_eq!(due.len(), 2);
    }

    #[test]
    fn test_next_due_in_returns_none_when_unseen() {
        let deck = Deck::new();
        let candidates = vec!["a".to_string(), "b".to_string()];
        assert!(deck.next_due_in(&candidates).is_none());
    }

    #[test]
    fn test_next_due_in_returns_none_when_due() {
        let mut deck = Deck::new();
        deck.record("a", true);
        make_due(&mut deck, "a");
        let candidates = vec!["a".to_string()];
        assert!(deck.next_due_in(&candidates).is_none());
    }

    #[test]
    fn test_next_due_in_returns_some_when_all_seen_not_due() {
        let mut deck = Deck::new();
        deck.record("a", true); // box 1, interval 60s
        let candidates = vec!["a".to_string()];
        let wait = deck.next_due_in(&candidates);
        assert!(wait.is_some());
        // Should be roughly 60 seconds (box 1 interval)
        assert!(wait.unwrap() <= 60);
        assert!(wait.unwrap() > 0);
    }

    #[test]
    fn test_next_due_in_returns_minimum_across_items() {
        let mut deck = Deck::new();
        deck.record("a", true); // box 1, interval 60s
        make_due(&mut deck, "a");
        deck.record("a", true); // box 2, interval 300s
        deck.record("b", true); // box 1, interval 60s
        let candidates = vec!["a".to_string(), "b".to_string()];
        let wait = deck.next_due_in(&candidates);
        assert!(wait.is_some());
        // b has shorter interval (60s) than a (300s)
        assert!(wait.unwrap() <= 60);
    }

    #[test]
    fn test_next_due_in_empty_candidates() {
        let deck = Deck::new();
        // No candidates means no items to wait for — returns None
        assert!(deck.next_due_in(&[]).is_none());
    }

    #[test]
    fn test_serde_roundtrip() {
        let mut deck = Deck::new();
        deck.record("x", true);
        deck.record("y", false);

        let json = serde_json::to_string(&deck).unwrap();
        let restored: Deck = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.len(), 2);
        assert_eq!(restored.get("x").unwrap().box_level, 1);
        assert_eq!(restored.get("y").unwrap().box_level, 0);
    }
}
