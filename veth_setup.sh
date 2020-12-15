#!/bin/bash

ip link add name s1-eth1 address 00:00:00:00:00:01 type veth peer name s1-eth2 address 00:00:00:00:00:02

ip link set dev s1-eth1 up
ip link set dev s1-eth2 up

# Set the MTU of these interfaces to be larger than default of 1500 bytes, 
# so that P4 behavioral-model testing can be done on jumbo frames.
ip link set s1-eth1 mtu 9500
ip link set s1-eth2 mtu 9500

# Disable IPv6 on all interfaces
sysctl net.ipv6.conf.s1-eth1.disable_ipv6=1
sysctl net.ipv6.conf.s1-eth2.disable_ipv6=1