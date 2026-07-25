//! 64-word dictionary for SAS encoding.
//!
//! Properties of this list:
//!
//! - Exactly 64 words (one per 6-bit nibble).
//! - All distinct first letter+second letter prefix (anti-homophone).
//! - All 4–7 ASCII letters (fast to read aloud, easy to type if needed).
//! - Common-vocabulary English so users without specialized training
//!   can repeat them on the first try.
//!
//! Bumping this list constitutes a wire-format change — bump
//! `INVITE_VERSION` in lockstep if the SAS layer is ever altered.

/// 64 distinct English words for short-authentication-string display.
///
/// Properties enforced by tests in this module:
/// - All distinct (no duplicates).
/// - Each is 4-7 lowercase ASCII letters.
/// - All 2-letter prefixes distinct (anti-homophone read-aloud).
/// - All pairs have Levenshtein distance ≥ 2 (anti-typo / anti-mishearing).
/// - None on the minimal English-language deny list.
/// - No triple-letter runs (easy to pronounce).
pub const SAS_WORDS: [&str; 64] = [
    "agile", "amuse", "apple", "basil", "blaze", "brick", "cargo", "cedar", "chess", "climb",
    "copper", "crane", "daisy", "decoy", "drift", "eagle", "ember", "exile", "fable", "flame",
    "frost", "globe", "gravy", "gusto", "happy", "hover", "igloo", "indigo", "ivory", "jolly",
    "juice", "kindly", "koala", "lemon", "lunar", "mango", "melon", "motor", "north", "nudge",
    "ocean", "olive", "panda", "plume", "quiet", "rebel", "ridge", "saber", "sleek", "sushi",
    "tiger", "trove", "ultra", "umbra", "vapor", "vivid", "wagon", "winter", "xenon", "xylo",
    "yacht", "yodel", "zebra", "zinc",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dictionary_has_exactly_64_words() {
        assert_eq!(SAS_WORDS.len(), 64);
    }

    #[test]
    fn dictionary_words_are_all_distinct() {
        let mut seen = std::collections::HashSet::new();
        for w in &SAS_WORDS {
            assert!(seen.insert(*w), "duplicate word: {w}");
        }
    }

    #[test]
    fn dictionary_words_are_4_to_7_ascii_letters() {
        for w in &SAS_WORDS {
            assert!(
                w.len() >= 4 && w.len() <= 7,
                "word {w:?} out of length range"
            );
            assert!(
                w.bytes().all(|b| b.is_ascii_lowercase()),
                "word {w:?} contains non-lowercase-ascii"
            );
        }
    }

    #[test]
    fn dictionary_first_two_letters_distinct() {
        let mut seen = std::collections::HashSet::new();
        for w in &SAS_WORDS {
            let prefix: String = w.chars().take(2).collect();
            assert!(seen.insert(prefix.clone()), "duplicate prefix: {prefix}");
        }
    }

    /// Compute the Levenshtein edit distance between two ASCII
    /// lowercase strings. Returns the minimum number of single-char
    /// insertions, deletions, or substitutions needed to transform
    /// `a` into `b`.
    fn levenshtein(a: &str, b: &str) -> usize {
        let a = a.as_bytes();
        let b = b.as_bytes();
        let (la, lb) = (a.len(), b.len());
        if la == 0 {
            return lb;
        }
        if lb == 0 {
            return la;
        }
        let mut prev: Vec<usize> = (0..=lb).collect();
        let mut curr: Vec<usize> = vec![0; lb + 1];
        for i in 1..=la {
            curr[0] = i;
            for j in 1..=lb {
                let cost = usize::from(a[i - 1] != b[j - 1]);
                curr[j] = (curr[j - 1] + 1).min(prev[j] + 1).min(prev[j - 1] + cost);
            }
            std::mem::swap(&mut prev, &mut curr);
        }
        prev[lb]
    }

    /// Pair-trust-grade requirement: no two dictionary words may
    /// differ by a single keystroke. A 1-character typo of "tiger"
    /// must NOT collide with another dictionary word, otherwise a
    /// user who slightly mishears the SAS could silently confirm
    /// a different value.
    #[test]
    fn dictionary_levenshtein_distance_at_least_2() {
        for (i, a) in SAS_WORDS.iter().enumerate() {
            for b in SAS_WORDS.iter().skip(i + 1) {
                let d = levenshtein(a, b);
                assert!(
                    d >= 2,
                    "SAS dictionary has Levenshtein-1 collision: {a:?} ↔ {b:?}"
                );
            }
        }
    }

    /// Catch obvious profanity / problematic words. This is a
    /// minimal English-language deny-list — the full linguistic
    /// audit (slang, regional vulgarities, non-English overlaps) is
    /// a curated step done out-of-band and tracked in the SAS
    /// curation checklist. Catches the most common regression
    /// surface: a future contributor adds an offensive word here
    /// without external review.
    #[test]
    fn dictionary_words_pass_minimal_deny_list() {
        const DENY: &[&str] = &[
            // Curse / vulgar
            "fuck", "shit", "damn", "cunt", "bitch", "crap", "piss", "ass", "asshole", "bastard",
            "dick", "cock", "pussy", // Drug / violence
            "kill", "rape", "drugs", "meth", "coke", "heroin",
            // Slurs (only common explicit; broader audit happens
            // out-of-band)
            "nazi", "slut", "whore",
        ];
        for w in &SAS_WORDS {
            assert!(
                !DENY.contains(w),
                "SAS dictionary contains denied word: {w:?}"
            );
        }
    }

    /// Pronunciation hint: no word should contain a triple letter
    /// (e.g. "bookkeeper") which is rare in everyday English and
    /// hard to read aloud quickly.
    #[test]
    fn dictionary_words_no_triple_letters() {
        for w in &SAS_WORDS {
            let b = w.as_bytes();
            for i in 2..b.len() {
                assert!(
                    !(b[i] == b[i - 1] && b[i - 1] == b[i - 2]),
                    "word {w:?} contains a triple letter"
                );
            }
        }
    }
}
