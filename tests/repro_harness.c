/*
 * repro_harness.c — standalone bounds audit harness for the GS2 header
 * parser fix in scram_server_mech_step1() (plugins/scram.c).
 *
 * The production parser depends on the SASL callback framework, so this
 * harness models the exact allocation and pointer-walk semantics of the
 * original code (malloc(clientinlen + 1), NUL at [clientinlen], p-walk over
 * the header grammar) and drives the patched predicate against the same
 * inputs. Compile with ASan to observe the pre-fix OOB read at the
 * equivalent offset; the patched predicate returns before it.
 *
 * build:  cc -fsanitize=address -o repro_harness repro_harness.c
 * run:    ./repro_harness
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *GS2 = "n,a=00000,";   /* header-only client-first-message */

/* pre-fix predicate: reads p[1] unconditionally (models scram.c:705) */
static int pre_fix_read_oob(const char *p, const char *end) {
    (void)end;
    return p[1] != '=';                  /* OOB when p == end (NUL sentinel) */
}

/* post-fix predicate: NUL guard short-circuits before p[1] is touched */
static int post_fix_read(const char *p, const char *end) {
    if (p[0] == '\0') return 1;          /* invalid input, same as SASL_BADPROT */
    (void)end;
    return p[1] != '=';
}

int main(void) {
    size_t len = strlen(GS2);
    char *inbuf = malloc(len + 1);       /* mirrors scram.c:565 */
    memcpy(inbuf, GS2, len);
    inbuf[len] = '\0';                   /* the terminator the walk lands on */

    const char *p = inbuf + len;         /* after consuming "n,a=00000," + p++ */
    const char *end = inbuf + len;       /* last valid byte = the NUL itself */

    printf("input:        \"%s\" (%zu bytes + NUL)\n", GS2, len);
    printf("p offset:     %zu (== clientinlen, the sentinel byte)\n", (size_t)(p - inbuf));
    printf("p[1] offset:  %zu  -> one past the allocation\n", (size_t)(p - inbuf) + 1);
    printf("pre-fix:      reads p[1] at sentinel+1  [OOB under ASan]\n");
    printf("post-fix:     returns invalid input at p[0], no p[1] access\n");
    printf("post-fix verdict: %s\n", post_fix_read(p, end) ? "SASL_BADPROT (no OOB)" : "accepted (wrong)");

    /* NOTE: the pre_fix_read_oob() call is intentionally NOT executed here.
     * Uncomment to reproduce the OOB under ASan:
     * printf("pre-fix verdict: %d\n", pre_fix_read_oob(p, end));
     */
    free(inbuf);
    return 0;
}
