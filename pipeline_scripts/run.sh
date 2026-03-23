#!/bin/bash
# 03/23/23 - Leighton Cook
set -e

# 1. Setup venv
python3 -m venv venv
source venv/bin/activate

# 2. Install dependencies (correct path)
pip install --upgrade pip
pip install -r requirements.txt   # <-- removed '../'

# 3. Run your normalization and generate summary
python src/security_event_processor.py
# summary report generation is already in the main processor now
# python src/summary_report_generator.py  <-- optional if merged