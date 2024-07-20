#!/bin/bash

### --- SETUP BUNDLE STRUCTURE --- ###
mkdir -p bare_bone.app/Contents/MacOS
mkdir -p bare_bone.app/Contents/Frameworks/ClockOpen.framework/Versions/A/{Headers,Resources}

# Create the header file for the dynamic library
cat << 'EOF' > bare_bone.app/Contents/Frameworks/ClockOpen.framework/Versions/A/Headers/ClockOpen.h
void openClock();
EOF

# Create the C source file for the dynamic library
cat << 'EOF' > ClockOpen.c
#include <stdlib.h>

void openClock() {
    system("open -a Clock");
}
EOF

# Compile the dynamic library
clang -dynamiclib -o bare_bone.app/Contents/Frameworks/ClockOpen.framework/Versions/A/ClockOpen ClockOpen.c

# Set the install name for the framework
install_name_tool -id @rpath/ClockOpen.framework/Versions/A/ClockOpen bare_bone.app/Contents/Frameworks/ClockOpen.framework/Versions/A/ClockOpen

# Create necessary symbolic links in the framework
ln -s A bare_bone.app/Contents/Frameworks/ClockOpen.framework/Versions/Current
ln -s Versions/Current/ClockOpen bare_bone.app/Contents/Frameworks/ClockOpen.framework/ClockOpen
ln -s Versions/Current/Headers bare_bone.app/Contents/Frameworks/ClockOpen.framework/Headers
ln -s Versions/Current/Resources bare_bone.app/Contents/Frameworks/ClockOpen.framework/Resources

# Create Info.plist for the Framework
cat << 'EOF' > bare_bone.app/Contents/Frameworks/ClockOpen.framework/Versions/A/Resources/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>ClockOpen</string>
</dict>
</plist>
EOF

# Create the C source file for the main binary
cat << 'EOF' > bare_bone.c
#include <stdio.h>
#include <stdlib.h>
#include "ClockOpen/ClockOpen.h"

int main() {
    system("open -a Calculator");
    openClock();
    return 0;
}
EOF

# Compile the main binary and link it to the framework
clang -o bare_bone.app/Contents/MacOS/bare_bone_exe bare_bone.c -Fbare_bone.app/Contents/Frameworks -framework ClockOpen -Wl,-rpath,@executable_path/../Frameworks

# Clean up C source files
rm bare_bone.c ClockOpen.c

# Creating Info.plist for the App
cat << 'EOF' > bare_bone.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>bare_bone_exe</string>
</dict>
</plist>
EOF

# Sign the application
codesign -f -s - --deep bare_bone.app