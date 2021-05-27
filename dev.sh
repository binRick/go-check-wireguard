#!/bin/bash
cmd="nodemon -w . -e go --delay 1 -x sh -- -c './run.sh $@||true'"
exec $cmd
