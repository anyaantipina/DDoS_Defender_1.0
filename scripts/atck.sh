# !/bin/bash
mac=$1
ip=$2
interval=$3
(sleep $interval && kill $$ ) | sudo /home/anna/hyenae-0.36-1/src/hyenae -a udp -I 1 -s $mac-$ip@%% -d %-%@5 -E 10

