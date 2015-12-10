#!/bin/sh

RHIZOME_STORE_PATH=$(./servald config paths | grep RHIZOME_STORE_PATH | awk 'BEGIN {FS=":"}; {print $2}')

echo "Stopping servald..."
./servald stop

echo "Purging $RHIZOME_STORE_PATH..."
rm -rf "$RHIZOME_STORE_PATH"