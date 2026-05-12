//! Re-Pair grammar compression — naive O(N²) implementation.

use std::collections::HashMap;

use thiserror::Error;

/// Errors the grammar layer can surface to callers.
#[derive(Debug, Error)]
pub enum GrammarError {
    /// A rule's non-terminal symbol points at an id that has no
    /// corresponding production — corrupt grammar.
    #[error("rule reference {0} out of range")]
    InvalidReference(u32),
    /// Rule expansion exceeded the safety-stop depth. Suggests a
    /// cycle in the rule graph (should be impossible for a valid
    /// grammar emitted by [`crate::compress`], so this indicates
    /// corruption or hand-crafted malicious input).
    #[error("rule expansion infinite-loops at id {0}")]
    InfiniteLoop(u32),
}

/// A single production rule: `lhs -> (right, left)`.
/// The non-terminal `lhs` expands to the pair `(left, right)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Rule {
    /// Non-terminal symbol id (always ≥ 256 since 0-255 are terminals).
    pub lhs: u32,
    /// First child symbol in the expansion (terminal or non-terminal).
    pub left: u32,
    /// Second child symbol in the expansion.
    pub right: u32,
}

/// The grammar emitted by [`compress`]: a top-level sequence of
/// symbols (a mix of terminals 0–255 and non-terminals ≥ 256) plus
/// the rules.
#[derive(Debug, Clone, PartialEq)]
pub struct Grammar {
    /// Top-level symbol sequence; replacing every non-terminal with
    /// its rule expansion (recursively) yields the original bytes.
    pub sequence: Vec<u32>,
    /// Production rules — one per minted non-terminal.
    pub rules: Vec<Rule>,
}

impl Grammar {
    /// "Size" of the grammar = `sequence.len() + 2 * rules.len()`.
    /// Smaller means better compression. The full input has length
    /// `decompressed.len()`.
    #[must_use]
    pub fn size(&self) -> usize {
        self.sequence.len() + 2 * self.rules.len()
    }
}

/// Compress `input` using Re-Pair. Each iteration finds the most
/// frequent adjacent pair, mints a new non-terminal for it, replaces
/// every occurrence, and records the rule. Stops when no pair appears
/// twice or more.
pub fn compress(input: &[u8]) -> Grammar {
    let mut sequence: Vec<u32> = input.iter().map(|&b| b as u32).collect();
    let mut rules: Vec<Rule> = Vec::new();
    let mut next_nonterminal: u32 = 256;

    loop {
        // Count adjacent pairs.
        let mut counts: HashMap<(u32, u32), usize> = HashMap::new();
        let mut i = 0;
        while i + 1 < sequence.len() {
            let key = (sequence[i], sequence[i + 1]);
            *counts.entry(key).or_insert(0) += 1;
            i += 1;
        }
        // Find the most frequent pair (must repeat ≥2 to be worth a
        // new rule).
        let best = counts
            .iter()
            .filter(|(_, c)| **c >= 2)
            .max_by_key(|(_, c)| **c)
            .map(|(k, _)| *k);
        let Some((a, b)) = best else {
            break;
        };
        // Mint a rule.
        let nt = next_nonterminal;
        next_nonterminal += 1;
        rules.push(Rule {
            lhs: nt,
            left: a,
            right: b,
        });
        // Replace every non-overlapping (a, b) occurrence with `nt`.
        let mut new_seq: Vec<u32> = Vec::with_capacity(sequence.len());
        let mut i = 0;
        while i < sequence.len() {
            if i + 1 < sequence.len() && sequence[i] == a && sequence[i + 1] == b {
                new_seq.push(nt);
                i += 2;
            } else {
                new_seq.push(sequence[i]);
                i += 1;
            }
        }
        sequence = new_seq;
    }

    Grammar { sequence, rules }
}

/// Decompress a grammar back to its source bytes.
pub fn decompress(grammar: &Grammar) -> Result<Vec<u8>, GrammarError> {
    // Build a rule-id → (left, right) lookup.
    let rule_by_lhs: HashMap<u32, (u32, u32)> = grammar
        .rules
        .iter()
        .map(|r| (r.lhs, (r.left, r.right)))
        .collect();

    fn expand(
        sym: u32,
        rules: &HashMap<u32, (u32, u32)>,
        out: &mut Vec<u8>,
        depth: usize,
    ) -> Result<(), GrammarError> {
        if depth > 1_000_000 {
            return Err(GrammarError::InfiniteLoop(sym));
        }
        if sym < 256 {
            out.push(sym as u8);
            return Ok(());
        }
        let &(left, right) = rules.get(&sym).ok_or(GrammarError::InvalidReference(sym))?;
        expand(left, rules, out, depth + 1)?;
        expand(right, rules, out, depth + 1)?;
        Ok(())
    }

    let mut out = Vec::new();
    for &sym in &grammar.sequence {
        expand(sym, &rule_by_lhs, &mut out, 0)?;
    }
    Ok(out)
}

/// Compression ratio: `grammar.size() / input.len()`. Below 1.0 means
/// the grammar is smaller than the input (compression achieved).
#[must_use]
pub fn compression_ratio(grammar: &Grammar, input_len: usize) -> f64 {
    if input_len == 0 {
        return 0.0;
    }
    grammar.size() as f64 / input_len as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_short_input() {
        let input = b"abcabcabc";
        let grammar = compress(input);
        let recovered = decompress(&grammar).unwrap();
        assert_eq!(recovered, input);
    }

    #[test]
    fn round_trip_random_input() {
        let input: Vec<u8> = (0..200).map(|i| ((i * 37 + 11) % 256) as u8).collect();
        let grammar = compress(&input);
        let recovered = decompress(&grammar).unwrap();
        assert_eq!(recovered, input);
    }

    #[test]
    fn repeating_input_compresses_well() {
        let input = b"abcdef".repeat(50); // 300 bytes of one repeated 6-byte pattern
        let grammar = compress(&input);
        let ratio = compression_ratio(&grammar, input.len());
        assert!(
            ratio < 0.3,
            "repeating pattern should compress to <30%; got {:.3}",
            ratio
        );
        assert_eq!(decompress(&grammar).unwrap(), input);
    }

    #[test]
    fn empty_input() {
        let grammar = compress(b"");
        assert!(grammar.sequence.is_empty());
        assert!(grammar.rules.is_empty());
        assert_eq!(decompress(&grammar).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn single_byte_no_rules() {
        let grammar = compress(b"x");
        assert_eq!(grammar.rules.len(), 0);
        assert_eq!(grammar.sequence, vec!['x' as u32]);
    }

    #[test]
    fn no_repetition_no_compression() {
        // Each byte appears at most once, so no pair repeats.
        let input: Vec<u8> = (0..50).collect();
        let grammar = compress(&input);
        assert_eq!(grammar.rules.len(), 0);
        assert_eq!(grammar.sequence.len(), input.len());
        assert_eq!(decompress(&grammar).unwrap(), input);
    }

    #[test]
    fn grammar_size_metric() {
        // 6 symbols + 2 rules → size = 6 + 4 = 10.
        let g = Grammar {
            sequence: vec![0, 1, 2, 3, 4, 5],
            rules: vec![
                Rule {
                    lhs: 256,
                    left: 0,
                    right: 1,
                },
                Rule {
                    lhs: 257,
                    left: 2,
                    right: 3,
                },
            ],
        };
        assert_eq!(g.size(), 10);
    }
}
