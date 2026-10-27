/*
 * Fixture libnvram — tiny shared library so binaries can carry a real
 * dynamic import of nvram_get(), the classic config source that analyzer
 * rule tables treat as attacker-influenceable (config_import).
 */
#include <stdlib.h>
#include <string.h>

static char value[256];

char *nvram_get(const char *key)
{
    const char *env = getenv(key);

    if (env == NULL) {
        env = "";
    }
    strncpy(value, env, sizeof(value) - 1);
    value[sizeof(value) - 1] = '\0';
    return value;
}
