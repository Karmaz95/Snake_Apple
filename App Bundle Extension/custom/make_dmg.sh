#!/bin/bash

# Variables
APP_NAME="bare_bone.app"
DMG_NAME="bare_bone.dmg"
TEMP_DIR="temp_dmg"

# Create a temporary directory and copy the app bundle into it
mkdir "$TEMP_DIR"
cp -R "$APP_NAME" "$TEMP_DIR"

# Create the DMG file
hdiutil create "$DMG_NAME" -srcfolder "$TEMP_DIR" -format UDZO -volname "Bare Bone App"

# Clean up
rm -rf "$TEMP_DIR"