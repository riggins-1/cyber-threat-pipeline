#!/bin/bash

# Configuration variables
URL="https://cisa.gov"
OUTPUT_FILE="data/known_exploited_vulnerabilities.json"
LOG_FILE="logs/project.log"

# Download the file using curl
# -f forces curl to fail on server errors, -L follows redirects
if curl -f -L -o "$OUTPUT_FILE" "$URL"; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - SUCCESS: KEV dataset downloaded successfully." >> "$LOG_FILE"
    echo "Download successful."
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: KEV dataset download failed." >> "$LOG_FILE"
    echo "Download failed!" >&2
    exit 1
fi
