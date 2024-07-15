# GS2 header parser state walk (scram_server_mech_step1)

Input grammar (RFC 5802 / RFC 7677 gs2 header):

    gs2-cbind-flag = "p=" cb-name / "n" / "y"
    gs2-authzid    = "a=" saslname
    gs2-header     = gs2-cbind-flag "," [ gs2-authzid ] ","

## Walk

1. `inbuf` = malloc(clientinlen + 1), copied input, NUL at [clientinlen].
2. `switch (p[0])` dispatches 'p'/'n'/'y'. For 'p', `p[1]` is read after
   confirming `p[0]=='p'`: worst case p[1] is the NUL (in-bounds). Safe.
3. Comma expected; `p++`.
4. Optional authzid: `p[0]=='a' && p[1]=='='`. If p[0] is NUL the left side
   fails and short-circuits — p[1] never read. Safe. Otherwise p[1] is
   within the allocation whenever p[0]=='a' (index <= clientinlen). Safe.
5. Comma expected again (or already consumed for the no-authzid form).
   On the *last* comma the code does `p[0] = '\0'; ... p++;`.
6. **p[1] read at :705.** If the message ended at that final comma, p is on
   the NUL at index clientinlen, and p[1] = index clientinlen+1 → 1 byte
   past the allocation. This is the bug.

## Why the fix is complete

Every read of p[1] is now either preceded by a confirmed non-NUL p[0]
(sites 592/648 by construction) or explicitly guarded (site 705). No other
p[1]/p[2] reads exist in step1; step2+ operate on the post-header remainder,
guaranteed non-empty by the step1 exit conditions.
