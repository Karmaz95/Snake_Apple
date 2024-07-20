#!/bin/bash

# This script installs the necessary tools, sets up the project, creates the TypeScript file, compiles it, and runs the script with the specified ASAR file path.
# https://medium.com/@karol-mazurek/cracking-macos-apps-39575dd672e0

# Define the TypeScript file and ASAR path
TS_FILE="calculate_hash.ts"
ASAR_PATH="$1"

# Step 1: Install Node.js and npm (if not installed)
echo "Ensure Node.js and npm are installed..."

# Step 2: Install TypeScript and ts-node globally
echo "Installing TypeScript and ts-node globally..."
npm install -g typescript ts-node

# Step 3: Initialize npm project (if not already done)
if [ ! -f "package.json" ]; then
  echo "Initializing npm project..."
  npm init -y
fi

# Step 4: Install dependencies
echo "Installing asar and @types/node..."
npm install asar
npm install --save-dev @types/node

# Step 5: Create TypeScript file
cat <<EOL > $TS_FILE
import * as crypto from 'crypto';
import * as asar from 'asar';
import * as fs from 'fs';

// Function to generate the integrity hash
const generateAsarIntegrity = (asarPath: string) => {
  const headerString = asar.getRawHeader(asarPath).headerString;
  const hash = crypto
    .createHash('sha256')
    .update(headerString)
    .digest('hex');

  return {
    algorithm: 'SHA256' as const,
    hash
  };
};

// Main script execution
const main = () => {
  if (process.argv.length !== 3) {
    console.error('Usage: node calculate_hash.ts <path_to_asar_file>');
    process.exit(1);
  }

  const asarPath = process.argv[2];

  // Check if the file exists
  if (!fs.existsSync(asarPath)) {
    console.error(\`File not found: \${asarPath}\`);
    process.exit(1);
  }

  const result = generateAsarIntegrity(asarPath);

  console.log(\`Algorithm: \${result.algorithm}\`);
  console.log(\`Hash: \${result.hash}\`);
};

// Run the script
main();
EOL

# Step 6: Compile TypeScript to JavaScript
echo "Compiling TypeScript to JavaScript..."
tsc $TS_FILE

# Step 7: Run the JavaScript file
echo "Running the script with ASAR path: $ASAR_PATH"
node calculate_hash.js "$ASAR_PATH"

echo "Done."