// https://medium.com/@karol-mazurek/cracking-macos-apps-39575dd672e0
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var crypto = require("crypto");
var asar = require("asar");
var fs = require("fs");
// Function to generate the integrity hash
var generateAsarIntegrity = function (asarPath) {
    var headerString = asar.getRawHeader(asarPath).headerString;
    var hash = crypto
        .createHash('sha256')
        .update(headerString)
        .digest('hex');
    return {
        algorithm: 'SHA256',
        hash: hash
    };
};
// Main script execution
var main = function () {
    if (process.argv.length !== 3) {
        console.error('Usage: node calculate_hash.ts <path_to_asar_file>');
        process.exit(1);
    }
    var asarPath = process.argv[2];
    // Check if the file exists
    if (!fs.existsSync(asarPath)) {
        console.error("File not found: ".concat(asarPath));
        process.exit(1);
    }
    var result = generateAsarIntegrity(asarPath);
    console.log("Algorithm: ".concat(result.algorithm));
    console.log("Hash: ".concat(result.hash));
};
// Run the script
main()