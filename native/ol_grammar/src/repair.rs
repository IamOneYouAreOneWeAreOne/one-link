//! Re-Pair grammar compression — naive O(N²) implementation.

use std::collections::{BTreeMap, HashMap};

use thiserror::Error;

type RuleTable = BTreeMap<u32, (u32, u32)>;
type ExpansionLengths = BTreeMap<u32, usize>;

/// Errors the grammar layer can surface to callers.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GrammarError {
    /// A rule's non-terminal symbol points at an id that has no
    /// corresponding production — corrupt grammar.
    #[error("rule reference {0} out of range")]
    InvalidReference(u32),
    /// A production directly references itself. This is impossible for a
    /// canonical grammar emitted by [`crate::compress`].
    #[error("rule expansion contains a self-cycle at id {0}")]
    InfiniteLoop(u32),
    /// A rule id is in the terminal namespace.
    #[error("rule lhs {0} is reserved for terminal bytes")]
    InvalidRuleLhs(u32),
    /// More than one rule defines the same non-terminal.
    #[error("duplicate production for rule id {0}")]
    DuplicateRule(u32),
    /// Canonical Re-Pair rules may only reference terminals or earlier rules.
    #[error("rule {lhs} has non-canonical forward dependency {child}")]
    NonCanonicalDependency {
        /// Rule being validated.
        lhs: u32,
        /// Child whose id is not lower than the parent id.
        child: u32,
    },
    /// The top-level sequence is too large to process safely.
    #[error("grammar sequence has {got} symbols; maximum is {max}")]
    SequenceTooLarge {
        /// Number of supplied symbols.
        got: usize,
        /// Maximum accepted symbols.
        max: usize,
    },
    /// The production table is too large to process safely.
    #[error("grammar has {got} rules; maximum is {max}")]
    TooManyRules {
        /// Number of supplied rules.
        got: usize,
        /// Maximum accepted rules.
        max: usize,
    },
    /// Expansion would exceed the bounded output envelope.
    #[error("grammar expands to more than {max} bytes")]
    OutputTooLarge {
        /// Maximum accepted output length.
        max: usize,
    },
    /// A bounded allocation could not be satisfied.
    #[error("unable to allocate bounded grammar workspace")]
    AllocationFailed,
}

/// Largest input on which the intentionally-simple O(N²) compressor runs.
/// Larger inputs are represented literally so callers never trigger a
/// super-linear CPU denial of service.
pub const MAX_COMPRESS_INPUT_BYTES: usize = 256 * 1024;
/// Maximum number of rules accepted from a serialized or hand-built grammar.
pub const MAX_GRAMMAR_RULES: usize = 65_536;
/// Maximum number of symbols in the top-level grammar sequence.
pub const MAX_GRAMMAR_SEQUENCE_SYMBOLS: usize = 1_048_576;
/// Maximum decompressed output produced by one grammar operation.
pub const MAX_DECOMPRESSED_BYTES: usize = 64 * 1024 * 1024;

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
        self.sequence
            .len()
            .saturating_add(self.rules.len().saturating_mul(2))
    }
}

/// Compress `input` using Re-Pair. Each iteration finds the most
/// frequent adjacent pair, mints a new non-terminal for it, replaces
/// every occurrence, and records the rule. Stops when no pair appears
/// twice or more.
pub fn compress(input: &[u8]) -> Grammar {
    let mut sequence: Vec<u32> = input.iter().map(|&b| u32::from(b)).collect();
    let mut rules: Vec<Rule> = Vec::new();
    if input.len() > MAX_COMPRESS_INPUT_BYTES {
        return Grammar { sequence, rules };
    }
    let mut next_nonterminal: u32 = 256;

    while rules.len() < MAX_GRAMMAR_RULES {
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
        // HashMap iteration order is deliberately randomized. Resolve equal
        // frequencies lexicographically so identical input always yields the
        // same grammar on every host and process.
        let mut best: Option<((u32, u32), usize)> = None;
        for (&pair, &count) in &counts {
            if count < 2 {
                continue;
            }
            if best.is_none_or(|(best_pair, best_count)| {
                count > best_count || (count == best_count && pair < best_pair)
            }) {
                best = Some((pair, count));
            }
        }
        let best = best.map(|(pair, _)| pair);
        let Some((a, b)) = best else {
            break;
        };
        // Mint a rule.
        let nt = next_nonterminal;
        let Some(next) = next_nonterminal.checked_add(1) else {
            break;
        };
        next_nonterminal = next;
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
    if grammar.sequence.len() > MAX_GRAMMAR_SEQUENCE_SYMBOLS {
        return Err(GrammarError::SequenceTooLarge {
            got: grammar.sequence.len(),
            max: MAX_GRAMMAR_SEQUENCE_SYMBOLS,
        });
    }
    if grammar.rules.len() > MAX_GRAMMAR_RULES {
        return Err(GrammarError::TooManyRules {
            got: grammar.rules.len(),
            max: MAX_GRAMMAR_RULES,
        });
    }

    let (rule_by_lhs, expansion_lengths) = build_rule_tables(&grammar.rules)?;

    let mut total_len = 0usize;
    for &sym in &grammar.sequence {
        let len = if sym < 256 {
            1
        } else {
            expansion_lengths
                .get(&sym)
                .copied()
                .ok_or(GrammarError::InvalidReference(sym))?
        };
        total_len = total_len
            .checked_add(len)
            .filter(|total| *total <= MAX_DECOMPRESSED_BYTES)
            .ok_or(GrammarError::OutputTooLarge {
                max: MAX_DECOMPRESSED_BYTES,
            })?;
    }

    let mut out = Vec::new();
    out.try_reserve_exact(total_len)
        .map_err(|_| GrammarError::AllocationFailed)?;
    let mut stack = Vec::new();
    stack
        .try_reserve(grammar.sequence.len())
        .map_err(|_| GrammarError::AllocationFailed)?;
    stack.extend(grammar.sequence.iter().rev().copied());
    while let Some(sym) = stack.pop() {
        if sym < 256 {
            out.push(u8::try_from(sym).map_err(|_| GrammarError::InvalidReference(sym))?);
            continue;
        }
        let &(left, right) = rule_by_lhs
            .get(&sym)
            .ok_or(GrammarError::InvalidReference(sym))?;
        stack
            .try_reserve(2)
            .map_err(|_| GrammarError::AllocationFailed)?;
        // LIFO order preserves the production's (left, right) byte order.
        stack.push(right);
        stack.push(left);
    }
    debug_assert_eq!(out.len(), total_len);
    Ok(out)
}

fn build_rule_tables(rules: &[Rule]) -> Result<(RuleTable, ExpansionLengths), GrammarError> {
    // A BTreeMap makes validation independent of caller-provided rule order.
    // Canonical Re-Pair productions only reference lower-numbered rules, so
    // cycles and arbitrarily deep recursive call stacks are rejected up front.
    let mut rule_by_lhs = BTreeMap::new();
    for rule in rules {
        if rule.lhs < 256 {
            return Err(GrammarError::InvalidRuleLhs(rule.lhs));
        }
        for child in [rule.left, rule.right] {
            if child >= rule.lhs {
                return Err(if child == rule.lhs {
                    GrammarError::InfiniteLoop(rule.lhs)
                } else {
                    GrammarError::NonCanonicalDependency {
                        lhs: rule.lhs,
                        child,
                    }
                });
            }
        }
        if rule_by_lhs
            .insert(rule.lhs, (rule.left, rule.right))
            .is_some()
        {
            return Err(GrammarError::DuplicateRule(rule.lhs));
        }
    }

    // Compute every production's exact expansion length before allocating or
    // emitting bytes. This rejects decompression bombs in O(rule count).
    let mut expansion_lengths = BTreeMap::new();
    for (&lhs, &(left, right)) in &rule_by_lhs {
        let child_len = |sym: u32| -> Result<usize, GrammarError> {
            if sym < 256 {
                Ok(1)
            } else {
                expansion_lengths
                    .get(&sym)
                    .copied()
                    .ok_or(GrammarError::InvalidReference(sym))
            }
        };
        let expanded = child_len(left)?
            .checked_add(child_len(right)?)
            .filter(|len| *len <= MAX_DECOMPRESSED_BYTES)
            .ok_or(GrammarError::OutputTooLarge {
                max: MAX_DECOMPRESSED_BYTES,
            })?;
        expansion_lengths.insert(lhs, expanded);
    }
    Ok((rule_by_lhs, expansion_lengths))
}

/// Compression ratio: `grammar.size() / input.len()`. Below 1.0 means
/// the grammar is smaller than the input (compression achieved).
#[must_use]
#[allow(clippy::cast_precision_loss)] // A diagnostic ratio is inherently approximate.
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
        let input: Vec<u8> = (0..200)
            .map(|i| u8::try_from((i * 37 + 11) % 256).unwrap_or_default())
            .collect();
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
            "repeating pattern should compress to <30%; got {ratio:.3}"
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

    #[test]
    fn equal_frequency_pairs_are_deterministic() {
        let input = b"ababcdcdababcdcd";
        let expected = compress(input);
        for _ in 0..64 {
            assert_eq!(compress(input), expected);
        }
    }

    #[test]
    fn oversized_compression_input_uses_bounded_literal_path() {
        let input = vec![b'x'; MAX_COMPRESS_INPUT_BYTES + 1];
        let grammar = compress(&input);
        assert!(grammar.rules.is_empty());
        assert_eq!(decompress(&grammar).unwrap(), input);
    }

    #[test]
    fn cyclic_and_duplicate_rules_fail_closed() {
        let cyclic = Grammar {
            sequence: vec![256],
            rules: vec![Rule {
                lhs: 256,
                left: 256,
                right: 0,
            }],
        };
        assert_eq!(decompress(&cyclic), Err(GrammarError::InfiniteLoop(256)));

        let duplicate = Grammar {
            sequence: vec![256],
            rules: vec![
                Rule {
                    lhs: 256,
                    left: 0,
                    right: 1,
                },
                Rule {
                    lhs: 256,
                    left: 2,
                    right: 3,
                },
            ],
        };
        assert_eq!(
            decompress(&duplicate),
            Err(GrammarError::DuplicateRule(256))
        );
    }

    #[test]
    fn exponential_expansion_is_rejected_before_allocation() {
        let mut rules = Vec::new();
        let mut previous = 0;
        for lhs in 256..283 {
            rules.push(Rule {
                lhs,
                left: previous,
                right: previous,
            });
            previous = lhs;
        }
        let bomb = Grammar {
            sequence: vec![previous],
            rules,
        };
        assert_eq!(
            decompress(&bomb),
            Err(GrammarError::OutputTooLarge {
                max: MAX_DECOMPRESSED_BYTES
            })
        );
    }

    #[test]
    fn resource_counts_and_invalid_references_are_rejected() {
        let oversized = Grammar {
            sequence: vec![0; MAX_GRAMMAR_SEQUENCE_SYMBOLS + 1],
            rules: Vec::new(),
        };
        assert!(matches!(
            decompress(&oversized),
            Err(GrammarError::SequenceTooLarge { .. })
        ));

        let missing = Grammar {
            sequence: vec![999],
            rules: Vec::new(),
        };
        assert_eq!(
            decompress(&missing),
            Err(GrammarError::InvalidReference(999))
        );
    }
}
