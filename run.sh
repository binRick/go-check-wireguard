#!/bin/bash
set -e

build_dir=./.bin
bin_name=check-wireguard

[[ -d $build_dir ]] || mkdir -p $build_dir

go build -o $build_dir/$bin_name .

cmd="$build_dir/$bin_name $ARGS"
exec $cmd
