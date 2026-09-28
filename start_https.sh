#!/bin/bash
# Usage: GPANEL_USER=op1 GPANEL_PASS='S3cure!' ./start_https.sh
cd "$(dirname "$0")"
pip3 install -r requirements.txt --quiet
python3 app.py
