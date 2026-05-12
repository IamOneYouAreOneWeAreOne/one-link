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
/// Every word has a distinct 2-letter prefix from every other word
/// (anti-homophone, anti-typo) and is 4-7 lowercase ASCII letters.
pub const SAS_WORDS: [&str; 64] = [
    "agile", "amber", "apple", "basil", "blaze", "brick", "cargo", "cedar",
    "chess", "climb", "copper", "crane", "daisy", "decoy", "drift", "eagle",
    "ember", "exile", "fable", "flame", "frost", "globe", "gravy", "gusto",
    "happy", "hover", "igloo", "indigo", "ivory", "jolly", "juice", "kindly",
    "koala", "lemon", "lunar", "mango", "melon", "motor", "north", "nudge",
    "ocean", "olive", "panda", "plume", "quiet", "rebel", "ridge", "saber",
    "sleek", "sushi", "tiger", "trove", "ultra", "umbra", "vapor", "vivid",
    "wagon", "winter", "xenon", "xylo", "yacht", "yodel", "zebra", "zinc",
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
}
