#!/bin/sh
./wccpscan.py -z -o ./wccp.tpl
zmap -M udp -s 2048 -p 2048 --probe-args=template:wccp.tpl -N 100 -f saddr,data -o wccp_results.csv
./wccpscan.py -z -i ./wccp_results.csv > validated_wccp_results.json