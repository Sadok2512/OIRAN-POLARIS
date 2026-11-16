#!/usr/bin/env bash
# Régénère l'objet eBPF précompilé (à lancer sur une machine AVEC clang,
# puis committer bpf/prebuilt/*). Le build sans clang vérifie que
# bpf/vtap.bpf.c est identique à bpf/prebuilt/vtap.bpf.c.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p prebuilt
clang -target bpf -O2 -g -D__TARGET_ARCH_x86 -Wall -Werror -c vtap.bpf.c -o prebuilt/vtap.bpf.o
cp vtap.bpf.c prebuilt/vtap.bpf.c
{
  clang --version | head -1
  sha256sum prebuilt/vtap.bpf.o prebuilt/vtap.bpf.c
} > prebuilt/PROVENANCE.txt
cat prebuilt/PROVENANCE.txt
