#!/bin/bash
set -e
cd $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

cmd="go mod edit -replace $1=$2"
set -x
eval $cmd
