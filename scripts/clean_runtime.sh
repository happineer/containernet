#!/bin/bash


# 1. delete remaining virtual network interfaces
vifs=`ifconfig | grep s1- | awk -F: '{print $1}'`
if [ -z "$vifs" ]; then
    echo "There is no virtual interface that need to be cleaned"
fi

for vif in $vifs
do
    echo "Down the virtual interface: "$vif
    sudo ip link set $vif down
    echo "Delete the virtual interface: "$vif
    sudo ip link delete $vif
done

# 2. delete remaining containers
containers=`sudo docker ps --all | grep 'mn\.' | awk '{print $NF}'`
if [ -z "$containers" ]; then
    echo "There is no containers that need to be cleaned"
fi
for ct in $containers
do
    echo "Stop the container: "$ct
    sudo docker stop $ct
    echo "Remove the container: "$ct
    sudo docker rm $ct
done


