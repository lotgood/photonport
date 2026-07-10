#!/bin/zsh
echo "ERROR: the monorepo iOS target is historical GPL-3.0 transition material and is intentionally not distributable." >&2
echo "Use the standalone PhotonPort iOS repository for builds and TestFlight; this script never deletes history or uploads the preserved target." >&2
exit 1