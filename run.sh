#!/bin/bash
cd "$(dirname "$0")"
pip3 install -r requirements.txt --quiet
python3 app.py
