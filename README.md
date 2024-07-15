# scram-gs2-oob

Minimal fix for a 1-byte heap out-of-bounds read in Cyrus SASL's SCRAM
GS2 header parser, found during an independent audit of the plugin
(`plugins/scram.c`).

## Root cause

`scram_server_mech_step1()` copies the client-first-message into a heap
buffer of `clientinlen + 1` bytes and walks a pointer `p` through the GS2
header (`n,` / `y,` / `p=cb-name,` / optional `a=<authzid>,`).

When the message consists solely of a complete GS2 header — e.g. `n,a=00000,`
— the walk consumes the trailing comma, `p++` lands on the NUL terminator at
index `clientinlen` (the last valid byte of the allocation), and the next
statement reads `p[1]`, one byte past the end. Unauthenticated, remote,
no session state required. CWE-125; ASan and Valgrind both flag it.

The offending line is unchanged since the original 2010 SCRAM
implementation — the read has been there since the mechanism shipped.

## Fix

One line, no behavior change for any in-bounds input:

```diff
-    if (p[1] != '=') {
+    if (p[0] == '\0' || p[1] != '=') {
```

The NUL check short-circuits before the out-of-bounds read; the
empty-remainder case returns the same `SASL_BADPROT` the malformed-input
path already returned.

## Bounds audit of sibling reads

- `scram.c:592` — `p[1]` read only after `p[0] == 'p'` confirmed on a
  buffer guaranteed non-empty: worst case p[1] is the NUL. Safe.
- `scram.c:648` — `p[0]=='a' && p[1]=='='`: short-circuits on NUL, and
  whenever `p[0]=='a'` the p[1] index is within the allocation. Safe.
- `scram.c:705` — **the bug.** Patched here.

## Contents

- `0001-scram-fix-gs2-oob-read.patch` — the patch, applies to master
- `notes/parser-walkthrough.md` — state-machine walk of every `p[1]` read

## Disclosure

Handled as a quiet fix publication: upstream maintainer activity has been
minimal for years; publishing here rather than waiting on a merge path.

## License

MIT
