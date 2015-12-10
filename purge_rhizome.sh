#!/bin/sh

RHIZOME_STORE_PATH=$(./servald config paths | grep RHIZOME_STORE_PATH | awk 'BEGIN {FS=":"}; {print $2}')

echo "Stopping servald..."
./servald stop

echo "Trying to purge $RHIZOME_STORE_PATH..."
read -p "Continue (y/n)? " choice
case "$choice" in 
  y|Y ) rm -rf "$RHIZOME_STORE_PATH";;
  * ) exit 1;;
esac
