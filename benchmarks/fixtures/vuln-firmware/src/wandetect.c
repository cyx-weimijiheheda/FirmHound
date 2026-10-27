/*
 * Fixture "wandetect" — intentionally vulnerable WAN check helper.
 *
 * Planted issue (see EXPECTED.md):
 *   V6 main: an nvram value flows through sprintf() into popen() —
 *      command injection from a config source (config values in this
 *      product line are settable through the web UI, hence reachable).
 */
#include <stdio.h>
#include <stdlib.h>

extern char *nvram_get(const char *key);

int main(void)
{
    char *wan_ip = nvram_get("wan_ipaddr");
    char cmd[128];
    FILE *fp;

    sprintf(cmd, "ping -c 1 %s", wan_ip);
    fp = popen(cmd, "r");
    if (fp != NULL) {
        pclose(fp);
    }
    return 0;
}
