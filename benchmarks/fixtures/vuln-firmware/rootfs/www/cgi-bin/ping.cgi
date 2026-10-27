#!/bin/sh
# Fixture CGI — intentionally vulnerable (see EXPECTED.md):
#   V7: the raw query string is expanded unquoted into a shell command —
#       textbook CGI command injection.
echo "Content-Type: text/plain"
echo ""
echo "ping result:"
ping -c 1 $QUERY_STRING
