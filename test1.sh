#!/bin/sh

pcap="$1"
log="$2"

[ -f "$pcap" ] || exit 1
[ -d "$log" ] || exit 1

tcpflow_output="$log"/tcpflow
foremost_output="$log"/foremost
tcpxtract_output="$log"/tcpxtract

mkdir -p "$tcpflow_output" || exit 1
cd "$tcpflow_output"
echo "$(basename "$0"): Running tcpflow"
tcpflow -b "$(ls -1 "$pcap" | awk '{print $5}')" -v -r "$pcap" 2> "$log"/tcpflow_log.txt 1> "$log"/tcpflow_log.txt
cd - > /dev/null
cd "$log"
echo "$(basename "$0"): Running foremost"
foremost -Q -T -o "$foremost_output" -i "$pcap"
mkdir -p "$tcpxtract_output"
echo "$(basename "$0"): Running tcpxtract"
tcpxtract -f "$pcap" -o "$tcpxtract_output" 2> "$log"/tcpxtract_log.txt 1> "$log"/tcpxtract_log.txt
cd - > /dev/null

#nautilus "$tcpxtract_output" 2> /dev/null > /dev/null &

