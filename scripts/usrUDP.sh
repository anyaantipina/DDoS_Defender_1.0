# !/bin/bash
mac1=$1
ip1=$2
mac2=$3
ip2=$4
interval=$5
(sleep $interval && kill $$ ) | sudo /home/anna/hyenae-0.36-1/src/hyenae -a udp -I 1 -s $mac1-$ip1@%% -d $mac2-$ip2@%% -e 500

