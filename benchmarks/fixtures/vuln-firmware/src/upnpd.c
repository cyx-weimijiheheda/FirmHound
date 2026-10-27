/*
 * Fixture "upnpd" — intentionally vulnerable UPnP daemon for analyzer tests.
 *
 * Planted issues (see EXPECTED.md):
 *   V4 handle_request: recv() data is strcpy()'d into a 64-byte stack
 *      buffer — remotely triggerable stack buffer overflow.
 *   V5 handle_request: the same network data is passed to syslog() as the
 *      format string — format-string vulnerability.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

static void handle_request(int sock)
{
    char request[1024];
    char action[64];
    ssize_t n = recv(sock, request, sizeof(request) - 1, 0);

    if (n <= 0) {
        return;
    }
    request[n] = '\0';

    /* V4: unbounded copy of network input into a small stack buffer. */
    strcpy(action, request);

    /* V5: attacker-controlled format string. */
    syslog(LOG_INFO, request);

    if (strcmp(action, "GetStatusInfo") == 0) {
        send(sock, "OK", 2, 0);
    }
}

int main(void)
{
    /* Socket setup is elided in the fixture; the analysis-relevant part is
     * handle_request() above. The daemon idles like a real service. */
    for (;;) {
        pause();
    }
    return 0;
}
