#!/bin/bash

ip link add dev s1-eth1 address 00:00:00:00:00:01 type veth peer name s1-eth2 address 00:00:00:00:00:02

ip link set s1-eth1 up
ip link set s1-eth2 up