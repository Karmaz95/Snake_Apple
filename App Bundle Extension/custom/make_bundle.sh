#!/bin/bash

### --- CREATE APP ICON --- ###
# Create a red icon using Python
python3 -c "from PIL import Image; Image.new('RGB', (1024, 1024), 'red').save('red_icon.png')"

# Prepare iconset directory
mkdir -p red_icon.iconset

# Convert the red icon to all necessary sizes and place them in the iconset directory
sips -z 16 16     red_icon.png --out red_icon.iconset/icon_16x16.png
sips -z 32 32     red_icon.png --out red_icon.iconset/icon_16x16@2x.png
sips -z 32 32     red_icon.png --out red_icon.iconset/icon_32x32.png
sips -z 64 64     red_icon.png --out red_icon.iconset/icon_32x32@2x.png
sips -z 128 128   red_icon.png --out red_icon.iconset/icon_128x128.png
sips -z 256 256   red_icon.png --out red_icon.iconset/icon_128x128@2x.png
sips -z 256 256   red_icon.png --out red_icon.iconset/icon_256x256.png
sips -z 512 512   red_icon.png --out red_icon.iconset/icon_256x256@2x.png
sips -z 512 512   red_icon.png --out red_icon.iconset/icon_512x512.png
sips -z 1024 1024 red_icon.png --out red_icon.iconset/icon_512x512@2x.png

# Convert iconset to icns
iconutil -c icns red_icon.iconset

# Clean up temporary files
rm -r red_icon.iconset red_icon.png

### --- MAKING BUNDLE --- ###
# Prepare a minimal bundle structure
mkdir -p bare_bone.app/Contents/MacOS

# Create a simple script that opens Calculator
echo '#!/bin/bash\nopen -a Calculator' > bare_bone.app/Contents/MacOS/bare_bone

# Add executable permissions to binary/script
chmod +x bare_bone.app/Contents/MacOS/bare_bone

# Creating Info.plist
echo '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>bare_bone_exe</string>
</dict>
</plist>' > bare_bone.app/Contents/Info.plist

# Renaming executable
mv bare_bone.app/Contents/MacOS/bare_bone bare_bone.app/Contents/MacOS/bare_bone_exe

# Creating Resources directory
mkdir -p bare_bone.app/Contents/Resources

# Move icon to Resources
mv red_icon.icns bare_bone.app/Contents/Resources/red_icon.icns

# Update Info.plist to use new icon
plutil -insert CFBundleIconFile -string "red_icon" bare_bone.app/Contents/Info.plist

# Creating Frameworks directory
mkdir -p bare_bone.app/Contents/Frameworks/ClockOpen.framework/Versions/A/Resources

# Create a script in the framework that opens Clock
echo '#!/bin/bash\nopen -a Clock' > bare_bone.app/Contents/Frameworks/ClockOpen.framework/Versions/A/ClockOpen
chmod +x bare_bone.app/Contents/Frameworks/ClockOpen.framework/Versions/A/ClockOpen

# Create necessary symbolic links in the framework
ln -s A bare_bone.app/Contents/Frameworks/ClockOpen.framework/Versions/Current
ln -s Versions/Current/ClockOpen bare_bone.app/Contents/Frameworks/ClockOpen.framework/ClockOpen
ln -s Versions/Current/Resources bare_bone.app/Contents/Frameworks/ClockOpen.framework/Resources

# Creating Info.plist for Framework
echo '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>ClockOpen</string>
</dict>
</plist>' > bare_bone.app/Contents/Frameworks/ClockOpen.framework/Versions/A/Resources/Info.plist

# Modify the main executable to use the script from ClockOpen Framework
echo 'SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"' >> bare_bone.app/Contents/MacOS/bare_bone_exe
echo '"$SCRIPT_DIR/../Frameworks/ClockOpen.framework/ClockOpen"' >> bare_bone.app/Contents/MacOS/bare_bone_exe

# Sign the application
codesign -f -s - --deep bare_bone.app