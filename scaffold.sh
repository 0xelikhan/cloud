#!/bin/bash
# Run from inside your cloned cloud repo:
#   git clone git@github.com:YOUR-USERNAME/cloud.git
#   cd cloud && bash scaffold.sh

set -e
echo "Scaffolding cloud..."

mkdir -p terraform/screenshots
mkdir -p sentinel-kql/screenshots
mkdir -p splunk-spl/screenshots
mkdir -p limacharlie/screenshots

find . -name "screenshots" -type d | while read d; do
  touch "$d/.gitkeep"
done

echo "Done."
echo ""
echo "Next: git add . && git commit -m 'Scaffold cloud repo' && git push"
