#!/usr/bin/env swift

import Foundation

// Function to check if a file is an executable Mach-O binary
func isExecutableMachO(filePath: String) -> Bool {
    let fileURL = URL(fileURLWithPath: filePath)
    return CFBundleCopyExecutableArchitecturesForURL(fileURL as CFURL) != nil
}

// Function to recursively process files in a directory
func processFiles(in directoryPath: String, recursive: Bool) {
    let fileManager = FileManager.default
    guard let enumerator = fileManager.enumerator(atPath: directoryPath) else {
        print("Error: Unable to access directory at \(directoryPath)")
        return
    }

    for case let file as String in enumerator {
        let fullPath = (directoryPath as NSString).appendingPathComponent(file)
        var isDirectory: ObjCBool = false
        fileManager.fileExists(atPath: fullPath, isDirectory: &isDirectory)
        
        if isDirectory.boolValue && !recursive {
            enumerator.skipDescendants()
            continue
        }

        if isExecutableMachO(filePath: fullPath) {
            print("Executable Mach-O: \(fullPath)")
        }
    }
}

// Argument handling
if CommandLine.arguments.count < 2 {
    print("Usage: swift ExecutableChecker.swift <directory_path> [-r]")
    exit(1)
}

let directoryPath = CommandLine.arguments[1]
let recursive = CommandLine.arguments.contains("-r")

processFiles(in: directoryPath, recursive: recursive)
