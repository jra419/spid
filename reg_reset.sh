#!/bin/bash

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

# THRIFT_PORT=$(cat /tmp/bmv2-s1-thrift-port)

THRIFT_PORT=36869

RUNTIME_CLI_PATH=~/p4tools/bmv2/targets/simple_switch/runtime_CLI

# Main Registers.

for i in {0..51}
do
  echo "register_reset reg_$i" | $RUNTIME_CLI_PATH --thrift-port $THRIFT_PORT &
done

# Threshold.

echo "register_reset reg_global_pkt" | $RUNTIME_CLI_PATH --thrift-port $THRIFT_PORT &
echo "register_reset reg_flow_global_pkt_cnt" | $RUNTIME_CLI_PATH --thrift-port $THRIFT_PORT &
echo "register_reset reg_flow_global_pkt_len" | $RUNTIME_CLI_PATH --thrift-port $THRIFT_PORT &
echo "register_reset reg_flow_pkt_cnt" | $RUNTIME_CLI_PATH --thrift-port $THRIFT_PORT &
echo "register_reset reg_flow_pkt_len" | $RUNTIME_CLI_PATH --thrift-port $THRIFT_PORT &

# Packet length stats.

echo "register_reset reg_cm_ip_len_ss_0" | $RUNTIME_CLI_PATH --thrift-port $THRIFT_PORT &
echo "register_reset reg_cm_ip_len_ss_1" | $RUNTIME_CLI_PATH --thrift-port $THRIFT_PORT &
echo "register_reset reg_cm_ip_len_ss_2" | $RUNTIME_CLI_PATH --thrift-port $THRIFT_PORT &
echo "register_reset reg_cm_ip_len_ss_final" | $RUNTIME_CLI_PATH --thrift-port $THRIFT_PORT &

# AMS.

echo "register_reset reg_sum_0" | $RUNTIME_CLI_PATH --thrift-port $THRIFT_PORT &
echo "register_reset reg_sum_1" | $RUNTIME_CLI_PATH --thrift-port $THRIFT_PORT &
echo "register_reset reg_sum_2" | $RUNTIME_CLI_PATH --thrift-port $THRIFT_PORT &

wait
