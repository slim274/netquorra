#!/usr/bin/env bash
set -e

cd "$(dirname "$0")/.."

if [ ! -f infrastructure/agent/.env ]; then
    echo "Network Agent environment file not found."
    exit 1
fi

set -a
source infrastructure/agent/.env
set +a

if [ -z "$NETQUORRA_AGENT_TOKEN" ]; then
    echo "NETQUORRA_AGENT_TOKEN is missing."
    exit 1
fi

exec env \
    -u GTK_EXE_PREFIX \
    -u GTK_PATH \
    -u GTK_MODULES \
    -u GTK_IM_MODULE_FILE \
    -u GIO_MODULE_DIR \
    -u GIO_EXTRA_MODULES \
    -u GIO_LAUNCHED_DESKTOP_FILE \
    -u GIO_LAUNCHED_DESKTOP_FILE_PID \
    GDK_BACKEND=x11 \
    dx serve --platform desktop