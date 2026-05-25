"""v0.21.x property-based tests (hypothesis).

Example-based tests assert one input → one output. Property-based
tests assert an INVARIANT that holds for EVERY input in a huge
generated space. They catch the bug-class example tests
systematically miss: 'the author didn't think of an empty string',
'the author didn't try unicode', 'the author didn't try a 65 KB
input', 'the author didn't try whitespace-only'.

Every test file in this directory uses hypothesis. Test failures
shrink the generated input to the minimal counterexample so the
bug is easy to reproduce.

Run with:

    python -m pytest tests/properties/ -v
"""
