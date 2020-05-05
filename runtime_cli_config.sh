#!/bin/bash

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

# THRIFT_PORT=$(cat /tmp/bmv2-s1-thrift-port)

THRIFT_PORT=36869

RUNTIME_CLI_PATH=~/p4tools/bmv2/targets/simple_switch/runtime_CLI

CRC32_CM_IP_1="set_crc32_parameters calc_0 0x5a0849e7 0xffffffff 0xffffffff true true"
CRC32_CM_IP_2="set_crc32_parameters calc_1 0x28ba08bb 0xffffffff 0xffffffff true true"
CRC32_CM_5T_1="set_crc32_parameters calc_3 0x5a0849e7 0xffffffff 0xffffffff true true"
CRC32_CM_5T_2="set_crc32_parameters calc_4 0x28ba08bb 0xffffffff 0xffffffff true true"

CRC32_AMS_1="set_crc32_parameters calc_13 0x5a0849e7 0xffffffff 0xffffffff true true"
CRC32_AMS_2="set_crc32_parameters calc_14 0x28ba08bb 0xffffffff 0xffffffff true true"
CRC32_AMS_3="set_crc32_parameters calc_15 0x3b328ffb 0xffffffff 0xffffffff true true"

echo "$CRC32_CM_IP_1" | $RUNTIME_CLI_PATH --thrift-port $THRIFT_PORT
echo "$CRC32_CM_IP_2" | $RUNTIME_CLI_PATH --thrift-port $THRIFT_PORT
echo "$CRC32_CM_5T_1" | $RUNTIME_CLI_PATH --thrift-port $THRIFT_PORT
echo "$CRC32_CM_5T_2" | $RUNTIME_CLI_PATH --thrift-port $THRIFT_PORT
echo "$CRC32_AMS_1" | $RUNTIME_CLI_PATH --thrift-port $THRIFT_PORT
echo "$CRC32_AMS_2" | $RUNTIME_CLI_PATH --thrift-port $THRIFT_PORT
echo "$CRC32_AMS_3" | $RUNTIME_CLI_PATH --thrift-port $THRIFT_PORT