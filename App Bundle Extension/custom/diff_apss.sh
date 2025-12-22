#!/usr/bin/env bash 

# Check if the correct number of arguments provided
if [ $# -ne 2 ]; then
    echo "Usage: $0 OLD_APP NEW_APP"
    echo "Example: $0 OLD/Fantastical.app NEW/Fantastical.app"
    exit 1
fi

OLD_APP="$1"
NEW_APP="$2"

# Check if directories exist
if [ ! -d "$OLD_APP" ]; then
    echo "Error: Old app directory '$OLD_APP' does not exist"
    exit 1
fi

if [ ! -d "$NEW_APP" ]; then
    echo "Error: New app directory '$NEW_APP' does not exist"
    exit 1
fi

echo "=========================================="
echo "APP PATCHING ANALYSIS"
echo "=========================================="
echo "Old App: $OLD_APP"
echo "New App: $NEW_APP"
echo "=========================================="

# Run diff with -r for recursive and -q for brief output
DIFF_OUTPUT=$(diff -rq "$OLD_APP" "$NEW_APP" 2>/dev/null)

# Process new files
echo -e "\n🆕 NEW FILES:"
echo "----------------------------------------"
NEW_LIST=$(echo "$DIFF_OUTPUT" | grep "Only in $NEW_APP" | sed "s|Only in $NEW_APP/||" | sed 's|: | → |')
if [ -n "$NEW_LIST" ]; then
    echo "$NEW_LIST" | while read -r line; do
        echo "  + $line"
    done
else
    echo "  (No new files)"
fi

# Process deleted files
echo -e "\n❌ DELETED FILES:"
echo "----------------------------------------"
DELETED_LIST=$(echo "$DIFF_OUTPUT" | grep "Only in $OLD_APP" | sed "s|Only in $OLD_APP/||" | sed 's|: | → |')
if [ -n "$DELETED_LIST" ]; then
    echo "$DELETED_LIST" | while read -r line; do
        echo "  - $line"
    done
else
    echo "  (No deleted files)"
fi

# Process modified files
echo -e "\n📝 MODIFIED FILES:"
echo "----------------------------------------"
MODIFIED_LIST=$(echo "$DIFF_OUTPUT" | grep "^Files.*differ$" | sed "s|Files $OLD_APP/||" | sed "s| and $NEW_APP/.*differ$||")
if [ -n "$MODIFIED_LIST" ]; then
    echo "$MODIFIED_LIST" | while read -r line; do
        echo "  ~ $line"
    done
else
    echo "  (No modified files)"
fi

# Find and report symlink changes
echo -e "\n🔗 SYMLINK CHANGES:"
echo "----------------------------------------"
SYMLINK_CHANGES=""

# Find all symlinks in OLD_APP
while IFS= read -r old_symlink; do
    rel_path="${old_symlink#$OLD_APP/}"
    new_symlink="$NEW_APP/$rel_path"
    
    if [ ! -L "$new_symlink" ]; then
        # Symlink was removed or converted to regular file
        SYMLINK_CHANGES="${SYMLINK_CHANGES}  - Removed: $rel_path\n"
    else
        # Check if symlink target changed
        old_target=$(readlink "$old_symlink")
        new_target=$(readlink "$new_symlink")
        if [ "$old_target" != "$new_target" ]; then
            SYMLINK_CHANGES="${SYMLINK_CHANGES}  ~ Modified: $rel_path\n"
            SYMLINK_CHANGES="${SYMLINK_CHANGES}      Old target: $old_target\n"
            SYMLINK_CHANGES="${SYMLINK_CHANGES}      New target: $new_target\n"
        fi
    fi
done < <(find "$OLD_APP" -type l)

# Find new symlinks in NEW_APP
while IFS= read -r new_symlink; do
    rel_path="${new_symlink#$NEW_APP/}"
    old_symlink="$OLD_APP/$rel_path"
    
    if [ ! -L "$old_symlink" ]; then
        # New symlink added
        new_target=$(readlink "$new_symlink")
        SYMLINK_CHANGES="${SYMLINK_CHANGES}  + Added: $rel_path → $new_target\n"
    fi
done < <(find "$NEW_APP" -type l)

if [ -n "$SYMLINK_CHANGES" ]; then
    echo -e "$SYMLINK_CHANGES"
else
    echo "  (No symlink changes)"
fi

# Count totals
NEW_COUNT=$(echo "$DIFF_OUTPUT" | grep -c "Only in $NEW_APP" 2>/dev/null || echo "0")
DELETED_COUNT=$(echo "$DIFF_OUTPUT" | grep -c "Only in $OLD_APP" 2>/dev/null || echo "0")
MODIFIED_COUNT=$(echo "$DIFF_OUTPUT" | grep -c "^Files.*differ$" 2>/dev/null || echo "0")

# Ensure counts are single integers
NEW_COUNT=$(echo "$NEW_COUNT" | head -n1 | tr -d '\n')
DELETED_COUNT=$(echo "$DELETED_COUNT" | head -n1 | tr -d '\n')
MODIFIED_COUNT=$(echo "$MODIFIED_COUNT" | head -n1 | tr -d '\n')

# Summary
echo -e "\n📊 SUMMARY:"
echo "=========================================="
echo "New files:      $NEW_COUNT"
echo "Deleted files:  $DELETED_COUNT"  
echo "Modified files: $MODIFIED_COUNT"
echo "Total changes:  $((NEW_COUNT + DELETED_COUNT + MODIFIED_COUNT))"
echo "=========================================="

# Binary file detection
BINARY_CHANGES=""
while IFS= read -r file; do
    if [ -n "$file" ]; then
        full_path="$NEW_APP/$file"
        if [ -f "$full_path" ] && [ ! -L "$full_path" ]; then
            file_type=$(file -b "$full_path" 2>/dev/null)
            if echo "$file_type" | grep -qE "(executable|shared library)"; then
                BINARY_CHANGES="$BINARY_CHANGES$file\n"
            fi
        fi
    fi
done <<< "$MODIFIED_LIST"

if [ -n "$BINARY_CHANGES" ]; then
    echo "⚠️  Binary files modified:"
    echo -e "$BINARY_CHANGES" | sed 's/^/    /'
fi