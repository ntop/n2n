#!/bin/bash

if [ ! "$COMMIT_HASH" = "" ]; then
  echo "Using COMMIT_HASH=$COMMIT_HASH"
  git reset --hard $COMMIT_HASH
fi

make