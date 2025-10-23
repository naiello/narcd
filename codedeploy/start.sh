#!/bin/bash
set -euxo pipefail
systemctl enable narcd
systemctl restart narcd
