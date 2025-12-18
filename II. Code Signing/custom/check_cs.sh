#!/bin/bash

# Usage: check_cs PATH

codesign -dvvvv --entitlements - "$1" 2>&1
