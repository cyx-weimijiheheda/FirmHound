/*
 * Fixture "httpd" — intentionally vulnerable web daemon for analyzer tests.
 *
 * Planted issues (see EXPECTED.md):
 *   V1 formPing : QUERY_STRING flows into system() via sprintf — command
 *                 injection, source and sink in the same function.
 *   V2 formLogin: HTTP_COOKIE is strcpy()'d into a 32-byte stack buffer —
 *                 stack buffer overflow, same-function source/sink.
 *   V3 hardcoded default credential compared against the cookie value.
 *
 * Handlers are registered GoAhead-style (websFormDefine("formXxx", fn)) so
 * generic handler-table recovery can attribute entry points.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Minimal stand-in for the GoAhead form registrar (statically linked,
 * like real Tenda/D-Link firmware): registration call sites carry
 * r0 = "formXxx" and r1 = handler address. */
static void websFormDefine(const char *name, void *handler)
{
    (void)name;
    (void)handler;
}

/* The GoAhead dispatcher matches request URIs against this prefix; the
 * literal "/goform/" string in .rodata is how real firmware carries it. */
static const char goform_prefix[] = "/goform/";

static int is_form_uri(const char *uri)
{
    return strncmp(uri, goform_prefix, sizeof(goform_prefix) - 1) == 0;
}

/* V1: command injection — getenv source, sprintf + system sinks. */
static void formPing(void)
{
    char *query = getenv("QUERY_STRING");
    char cmd[256];

    if (query == NULL) {
        query = "";
    }
    sprintf(cmd, "ping -c 1 %s", query);
    system(cmd);
}

/* V2: stack overflow — getenv source, strcpy sink, 32-byte destination. */
static void formLogin(void)
{
    char *cookie = getenv("HTTP_COOKIE");
    char session_user[32];

    if (cookie == NULL) {
        cookie = "";
    }
    strcpy(session_user, cookie);

    /* V3: hardcoded default credential. */
    if (strcmp(session_user, "admin:defaultpass") == 0) {
        formPing();
    }
}

int main(void)
{
    websFormDefine("formPing", (void *)formPing);
    websFormDefine("formLogin", (void *)formLogin);

    if (!is_form_uri("/goform/formPing")) {
        return 1;
    }
    for (;;) {
        pause();
    }
    return 0;
}
