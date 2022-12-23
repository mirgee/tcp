#!/bin/bash
cargo build
sudo ./target/debug/my-rtcp &
pid=$!
sleep 1
sudo route add -host 10.0.0.1 -interface utun4
# sudo kill $pid
trap "kill $pid" INT TERM
wait $pid
