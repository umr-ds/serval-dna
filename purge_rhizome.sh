#!/bin/sh

RHIZOME_STORE_PATH=$(./servald config paths | grep RHIZOME_STORE_PATH | awk 'BEGIN {FS=":"}; {print $2}')

echo "Stopping servald..."
./servald stop

echo

read -p "Trying to purge $RHIZOME_STORE_PATH. Continue (y/n)? " choice
case "$choice" in 
  y|Y ) 
    echo "Purging $RHIZOME_STORE_PATH..."
    rm -rf "$RHIZOME_STORE_PATH"
  ;;
  * ) exit 1;;
esac
