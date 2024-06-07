#!/bin/bash

### EXPECTED RESULTS:
# Only 0x10000 with double entitlement ALLOWED to inject dylibs using DYLD_INSERT_LIBRARIES - 25.03.2024 (expected behaviour)
# Multiple issue with DEV pruned reported to Apple -> 

###############
### STARTER ###
###############

# ent1.plist
echo '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-dyld-environment-variables</key>
    <true/>
</dict>
</plist>''' > ent1.plist

# ent2.plist
echo '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-dyld-environment-variables</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
</dict>
</plist>''' > ent2.plist

# hello.c
echo '''#include <stdio.h>
int main() {
    // Print "Hello, World!" to the console
    printf("Hello, World!\n");
    return 0;
}''' > hello.c

# NORMAL USER ACCESS BINARY SAMPLE
clang hello.c -o hello
# NORMAL USER ACCESS BINARY SAMPLE - RESTRICTED SEGMENT
mkdir RESTRICTED
clang -sectcreate __RESTRICT __restrict /dev/null hello.c -o RESTRICTED/hello_restricted
# SUIDS
mkdir SUIDS
# SUIDS - RESTRICTED SEGMENT
mkdir RESTRICTED_SUIDS
# SGIDS
mkdir SGIDS
# SGIDS - RESTRICTED SEGMENT
mkdir RESTRICTED_SGIDS


##############
### NORMAL ###
##############

## SIGNING
# CS_RESTRICT
cp hello hello_800
codesign -s - -f --option=0x800 hello_800
# CS_REQUIRE_LV
cp hello hello_2000
codesign -s - -f --option=0x2000 hello_2000
# CS_RUNTIME
cp hello hello_10000
codesign -s - -f --option=0x10000 hello_10000
# CS_RESTRICT + CS_REQUIRE_LV
cp hello hello_2800
codesign -s - -f --option=0x2800 hello_2800
# CS_RESTRICT + CS_RUNTIME
cp hello hello_10800
codesign -s - -f --option=0x10800 hello_10800
# CS_REQUIRE_LV + CS_RUNTIME
cp hello hello_12000
codesign -s - -f --option=0x12000 hello_12000
# CS_RESTRICT + CS_REQUIRE_LV + CS_RUNTIME
cp hello hello_12800
codesign -s - -f --option=0x12800 hello_12800

## SIGNING WITH ENTITLEMENTS - ent1.plist
cp hello hello_ent1
codesign --entitlements ent1.plist -s - -f hello_ent1
# CS_RESTRICT
cp hello hello_800_ent1
codesign --entitlements ent1.plist -s - -f --option=0x800 hello_800_ent1
# CS_REQUIRE_LV
cp hello hello_2000_ent1
codesign --entitlements ent1.plist -s - -f --option=0x2000 hello_2000_ent1
# CS_RUNTIME
cp hello hello_10000_ent1
codesign --entitlements ent1.plist -s - -f --option=0x10000 hello_10000_ent1
# CS_RESTRICT + CS_REQUIRE_LV
cp hello hello_2800_ent1
codesign --entitlements ent1.plist -s - -f --option=0x2800 hello_2800_ent1
# CS_RESTRICT + CS_RUNTIME
cp hello hello_10800_ent1
codesign --entitlements ent1.plist -s - -f --option=0x10800 hello_10800_ent1
# CS_REQUIRE_LV + CS_RUNTIME
cp hello hello_12000_ent1
codesign --entitlements ent1.plist -s - -f --option=0x12000 hello_12000_ent1
# CS_RESTRICT + CS_REQUIRE_LV + CS_RUNTIME
cp hello hello_12800_ent1
codesign --entitlements ent1.plist -s - -f --option=0x12800 hello_12800_ent1

## SIGNING WITH ENTITLEMENTS - ent2.plist
cp hello hello_ent2
codesign --entitlements ent2.plist -s - -f hello_ent2
# CS_RESTRICT
cp hello hello_800_ent2
codesign --entitlements ent2.plist -s - -f --option=0x800 hello_800_ent2
# CS_REQUIRE_LV
cp hello hello_2000_ent2
codesign --entitlements ent2.plist -s - -f --option=0x2000 hello_2000_ent2
# CS_RUNTIME
cp hello hello_10000_ent2
codesign --entitlements ent2.plist -s - -f --option=0x10000 hello_10000_ent2
# CS_RESTRICT + CS_REQUIRE_LV
cp hello hello_2800_ent2
codesign --entitlements ent2.plist -s - -f --option=0x2800 hello_2800_ent2
# CS_RESTRICT + CS_RUNTIME
cp hello hello_10800_ent2
codesign --entitlements ent2.plist -s - -f --option=0x10800 hello_10800_ent2
# CS_REQUIRE_LV + CS_RUNTIME
cp hello hello_12000_ent2
codesign --entitlements ent2.plist -s - -f --option=0x12000 hello_12000_ent2
# CS_RESTRICT + CS_REQUIRE_LV + CS_RUNTIME
cp hello hello_12800_ent2
codesign --entitlements ent2.plist -s - -f --option=0x12800 hello_12800_ent2


##################
### RESTRICTED ###
##################

## SIGNING 
# CS_RESTRICT
cp RESTRICTED/hello_restricted RESTRICTED/hello_restricted_800
codesign -s - -f --option=0x800 RESTRICTED/hello_restricted_800
# CS_REQUIRE_LV
cp RESTRICTED/hello_restricted RESTRICTED/hello_restricted_2000
codesign -s - -f --option=0x2000 RESTRICTED/hello_restricted_2000
# CS_RUNTIME
cp RESTRICTED/hello_restricted RESTRICTED/hello_restricted_10000
codesign -s - -f --option=0x10000 RESTRICTED/hello_restricted_10000
# CS_RESTRICT + CS_REQUIRE_LV
cp RESTRICTED/hello_restricted RESTRICTED/hello_restricted_2800
codesign -s - -f --option=0x2800 RESTRICTED/hello_restricted_2800
# CS_RESTRICT + CS_RUNTIME
cp RESTRICTED/hello_restricted RESTRICTED/hello_restricted_10800
codesign -s - -f --option=0x10800 RESTRICTED/hello_restricted_10800
# CS_REQUIRE_LV + CS_RUNTIME
cp RESTRICTED/hello_restricted RESTRICTED/hello_restricted_12000
codesign -s - -f --option=0x12000 RESTRICTED/hello_restricted_12000
# CS_RESTRICT + CS_REQUIRE_LV + CS_RUNTIME
cp RESTRICTED/hello_restricted RESTRICTED/hello_restricted_12800
codesign -s - -f --option=0x12800 RESTRICTED/hello_restricted_12800

## SIGNING WITH ENTITLEMENTS
# ent1
cp RESTRICTED/hello_restricted RESTRICTED/hello_restricted_ent1
codesign --entitlements ent1.plist -s - -f RESTRICTED/hello_restricted_ent1
# CS_RESTRICT
cp RESTRICTED/hello_restricted RESTRICTED/hello_restricted_800_ent1
codesign --entitlements ent1.plist -s - -f --option=0x800 RESTRICTED/hello_restricted_800_ent1
# CS_REQUIRE_LV
cp RESTRICTED/hello_restricted RESTRICTED/hello_restricted_2000_ent1
codesign --entitlements ent1.plist -s - -f --option=0x2000 RESTRICTED/hello_restricted_2000_ent1
# CS_RUNTIME
cp RESTRICTED/hello_restricted RESTRICTED/hello_restricted_10000_ent1
codesign --entitlements ent1.plist -s - -f --option=0x10000 RESTRICTED/hello_restricted_10000_ent1
# CS_RESTRICT + CS_REQUIRE_LV
cp RESTRICTED/hello_restricted RESTRICTED/hello_restricted_2800_ent1
codesign --entitlements ent1.plist -s - -f --option=0x2800 RESTRICTED/hello_restricted_2800_ent1
# CS_RESTRICT + CS_RUNTIME
cp RESTRICTED/hello_restricted RESTRICTED/hello_restricted_10800_ent1
codesign --entitlements ent1.plist -s - -f --option=0x10800 RESTRICTED/hello_restricted_10800_ent1
# CS_REQUIRE_LV + CS_RUNTIME
cp RESTRICTED/hello_restricted RESTRICTED/hello_restricted_12000_ent1
codesign --entitlements ent1.plist -s - -f --option=0x12000 RESTRICTED/hello_restricted_12000_ent1
# CS_RESTRICT + CS_REQUIRE_LV + CS_RUNTIME
cp RESTRICTED/hello_restricted RESTRICTED/hello_restricted_12800_ent1
codesign --entitlements ent1.plist -s - -f --option=0x12800 RESTRICTED/hello_restricted_12800_ent1

## SIGNING WITH ENTITLEMENTS - ent2.plist
cp RESTRICTED/hello_restricted RESTRICTED/hello_restricted_ent2
codesign --entitlements ent2.plist -s - -f RESTRICTED/hello_restricted_ent2
# CS_RESTRICT
cp RESTRICTED/hello_restricted RESTRICTED/hello_restricted_800_ent2
codesign --entitlements ent2.plist -s - -f --option=0x800 RESTRICTED/hello_restricted_800_ent2
# CS_REQUIRE_LV
cp RESTRICTED/hello_restricted RESTRICTED/hello_restricted_2000_ent2
codesign --entitlements ent2.plist -s - -f --option=0x2000 RESTRICTED/hello_restricted_2000_ent2
# CS_RUNTIME
cp RESTRICTED/hello_restricted RESTRICTED/hello_restricted_10000_ent2
codesign --entitlements ent2.plist -s - -f --option=0x10000 RESTRICTED/hello_restricted_10000_ent2
# CS_RESTRICT + CS_REQUIRE_LV
cp RESTRICTED/hello_restricted RESTRICTED/hello_restricted_2800_ent2
codesign --entitlements ent2.plist -s - -f --option=0x2800 RESTRICTED/hello_restricted_2800_ent2
# CS_RESTRICT + CS_RUNTIME
cp RESTRICTED/hello_restricted RESTRICTED/hello_restricted_10800_ent2
codesign --entitlements ent2.plist -s - -f --option=0x10800 RESTRICTED/hello_restricted_10800_ent2
# CS_REQUIRE_LV + CS_RUNTIME
cp RESTRICTED/hello_restricted RESTRICTED/hello_restricted_12000_ent2
codesign --entitlements ent2.plist -s - -f --option=0x12000 RESTRICTED/hello_restricted_12000_ent2
# CS_RESTRICT + CS_REQUIRE_LV + CS_RUNTIME
cp RESTRICTED/hello_restricted RESTRICTED/hello_restricted_12800_ent2
codesign --entitlements ent2.plist -s - -f --option=0x12800 RESTRICTED/hello_restricted_12800_ent2


##############
### BACKUP ###
##############
mkdir ../BACKUP
mv hello.c ent1.plist ent2.plist "$0" ../BACKUP/


#############
### SUIDS ###
#############
cp * SUIDS/
sudo chown -R root:wheel SUIDS 
sudo chmod -R +s SUIDS/*


##################################
### SUIDS - RESTRICTED SEGMENT ###
##################################
cp * RESTRICTED_SUIDS/
sudo chown -R root:wheel RESTRICTED_SUIDS 
sudo chmod -R +s RESTRICTED_SUIDS/*


#############
### SGIDS ###
#############
cp * SGIDS/
sudo chown -R root:wheel SGIDS 
sudo chmod -R +s SGIDS/*


##################################
### SGIDS - RESTRICTED SEGMENT ###
##################################
cp * RESTRICTED_SGIDS/
sudo chown -R root:wheel RESTRICTED_SGIDS 
sudo chmod -R +s RESTRICTED_SGIDS/*


#####################
### TESTING PHASE ###
#####################
listFilesOnly() {
    find . -type f ! -name "_testing.log"
}

testingCommand() {
    local file="$1"
    local log_file="$(basename "$(pwd)")_testing.log"  # Create log file based on current directory
    echo "$file" | tee -a "$log_file"
    CrimsonUroboros -p "$file" --test_prune_dyld --injectable_dyld --test_insert_dylib --test_dyld_print_to_file | tee -a "$log_file"
}

executeTestingCommandOnFiles() {
    for f in $(listFilesOnly); do
        testingCommand "$f"
    done
}

executeTestingCommandOnFiles

##################################
### CREATE FINAL CSV FOR EXCEL ###
##################################
paste -d ',' - - - - - < sample_testing.log | sed "s/:/,/g" > "final_$(date +%d_%m_%Y).csv"
