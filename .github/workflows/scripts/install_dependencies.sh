#!/bin/sh -e
#
# Copyright 2023 The Keylime Authors
# SPDX-License-Identifier: Apache-2.0
#
COMMON="helm"
COMMAND_CHECK="helm docker"

case "${DISTRO}" in
debian:*|ubuntu:*)
    export DEBIAN_FRONTEND=noninteractive
    apt clean
    apt update
    # We get some errors once in a while, so let's try a few times.
    for i in 1 2 3; do
        apt -y install ${COMMON} && break
        sleep ${i}
    done
    ;;
esac

echo "================= SYSTEM ================="
cat /etc/os-release
uname -a
echo "=========================================="

for command in ${COMMAND_CHECK}; do
    command -v "${command}"
done
