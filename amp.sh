#!/bin/bash -e

ROOT="$(realpath "$(dirname "$0")")"
POLICY="$(make-sandbox-policy "$ROOT")"

sandbox-exec -p "$POLICY" amp
