#!/bin/sh
set -euxo pipefail
echo "Starting Testing ..."
python3 -u /pysyslog/pysyslog.py test
python3 -u /pysyslog/msgtest.py
