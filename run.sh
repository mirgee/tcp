#!/bin/bash
cargo build
ext=$?
if [[ $ext -ne 0 ]]; then
	exit $ext
fi
sudo ./target/debug/my-rtcp &
pid=$!
sleep 1
sudo route add -host 10.0.0.2 -interface utun4
trap "sudo kill $pid" INT TERM
wait $pid
