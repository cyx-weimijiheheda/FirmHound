#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void handle_ping(void) {
    const char *query = getenv("QUERY_STRING");
    char command[256];

    if (query == NULL) {
        return;
    }
    /* Intentional command-injection fixture: query is not encoded. */
    snprintf(command, sizeof(command), "ping -c 1 %s", query);
    system(command);
}

static void handle_diag(void) {
    const char *value = getenv("DIAG");
    char local[32];

    if (value == NULL) {
        return;
    }
    /* Intentional stack-overflow fixture. */
    strcpy(local, value);
    puts(local);
}

static void handle_log(void) {
    const char *format = getenv("LOG_FORMAT");

    if (format == NULL) {
        return;
    }
    /* Intentional format-string fixture. */
    printf(format);
}

static void handle_download(void) {
    const char *name = getenv("DOWNLOAD_NAME");
    char path[256];
    FILE *stream;

    if (name == NULL) {
        return;
    }
    /* Intentional path-traversal fixture: no canonicalisation or allow-list. */
    snprintf(path, sizeof(path), "/tmp/downloads/%s", name);
    stream = fopen(path, "wb");
    if (stream != NULL) {
        fputs("lab fixture\n", stream);
        fclose(stream);
    }
}

static void handle_copy(void) {
    const char *value = getenv("COPY_VALUE");
    char local[24];

    if (value == NULL) {
        return;
    }
    /* A second unsafe-copy site gives triage and ranking more than one hit. */
    strcpy(local, value);
    puts(local);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "all";

    if (strcmp(mode, "ping") == 0 || strcmp(mode, "all") == 0) {
        handle_ping();
    }
    if (strcmp(mode, "diag") == 0 || strcmp(mode, "all") == 0) {
        handle_diag();
    }
    if (strcmp(mode, "log") == 0 || strcmp(mode, "all") == 0) {
        handle_log();
    }
    if (strcmp(mode, "download") == 0 || strcmp(mode, "all") == 0) {
        handle_download();
    }
    if (strcmp(mode, "copy") == 0 || strcmp(mode, "all") == 0) {
        handle_copy();
    }
    return 0;
}
