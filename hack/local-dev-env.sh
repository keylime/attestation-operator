#!/bin/bash

# path where this script resides
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

export KEYLIME_REGISTRAR_URL="https://127.0.0.1:8891"
export KEYLIME_VERIFIER_URL="https://127.0.0.1:8881"
export KEYLIME_CLIENT_KEY="${SCRIPT_DIR}/client-private.pem"
export KEYLIME_CLIENT_CERT="${SCRIPT_DIR}/client-cert.crt"
export KEYLIME_REGISTRAR_SYNCHRONIZER_INTERVAL_DURATION="10s"
