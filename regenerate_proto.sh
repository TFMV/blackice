#!/bin/bash
# Script to regenerate protobuf code with enhanced Anomaly fields

set -e

BASEDIR=$(pwd)
echo "Working directory: $BASEDIR"

# Create a temporary output directory
OUTPUT_DIR="$BASEDIR/proto_build"
mkdir -p "$OUTPUT_DIR/blackice/proto/blackice/v1"
echo "Created output directory: $OUTPUT_DIR"

# Create a temporary proto directory structure
TEMP_DIR="$BASEDIR/temp_proto"
mkdir -p "$TEMP_DIR/blackice/proto/blackice/v1"
echo "Created temporary directory: $TEMP_DIR"

# Copy proto files to temp directory with the correct structure
cp "$BASEDIR"/proto/blackice/v1/*.proto "$TEMP_DIR/blackice/proto/blackice/v1/"
echo "Copied proto files to temporary directory"

# Run protoc from the temp directory
echo "Generating protobuf code..."
cd "$TEMP_DIR"

for proto_file in "$TEMP_DIR"/blackice/proto/blackice/v1/*.proto; do
    filename=$(basename "$proto_file")
    echo "Processing: $filename"
    
    protoc \
        -I=. \
        --go_out="$OUTPUT_DIR" \
        --go_opt=paths=source_relative \
        --go-grpc_out="$OUTPUT_DIR" \
        --go-grpc_opt=paths=source_relative \
        "blackice/proto/blackice/v1/$filename"
done

# Clean up
cd "$BASEDIR"
rm -rf "$TEMP_DIR"
echo "Removed temporary directory"

echo "Proto file generation complete. Generated files are in $OUTPUT_DIR"
echo "You can now manually move the files to the correct location." 