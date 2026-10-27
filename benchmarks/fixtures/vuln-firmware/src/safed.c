/*
 * Fixture "safed" — NEGATIVE CONTROL. This program touches the same kind
 * of input as httpd but handles it defensively:
 *   - whitelist comparison (strncmp) before acting,
 *   - length check (strlen) before copying,
 *   - bounded snprintf() into the destination buffer,
 *   - no system()/popen()/strcpy() anywhere.
 *
 * Expected analyzer behaviour: at most low-score candidates, and no
 * confirmed/high-confidence verdict. If a tool flags this binary as a
 * confirmed vulnerability, that is a false positive (see EXPECTED.md).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void handle_status(void)
{
    char *query = getenv("QUERY_STRING");
    char reply[64];

    if (query == NULL) {
        return;
    }
    if (strlen(query) >= sizeof(reply)) {
        return;
    }
    if (strncmp(query, "status", 6) != 0 && strncmp(query, "version", 7) != 0) {
        return;
    }
    snprintf(reply, sizeof(reply), "mode=%s", query);
    puts(reply);
}

int main(void)
{
    handle_status();
    return 0;
}
