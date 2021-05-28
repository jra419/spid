#!/bin/bash

cleanup() {
	sudo pkill -f main.py
	sudo pkill -f simple_switch_grpc
	sudo pkill -f onos
	bash veth_teardown.sh
	exit
}

trap cleanup EXIT

echo "--------------------"
echo "Starting veth interfaces and cleaning up"
echo "--------------------"

sudo bash veth_teardown.sh
sudo bash veth_setup.sh

echo "--------------------"
echo "ML python REST script"
echo "--------------------"

cd spid_ml || exit

python3 main.py --kmeans --dbscan &

sleep 5

echo "--------------------"
echo "Starting ONOS"
echo "--------------------"

cd ~/onos/ || exit

sleep 5

export ONOS_APPS=drivers.bmv2,proxyarp,lldpprovider,hostprovider,fwd,gui2,p4dma.pipeconf,p4dma.dma

bazel run onos-local -- clean &

sleep 30

tail -f /tmp/onos-2.2.9-SNAPSHOT/onos.log | while read -r LOGLINE
do
   [[ "${LOGLINE}" == *"Application org.onosproject.drivers.cisco.netconf has been installed"* ]] && pkill -P $$ tail
done
echo "
----
----
[MATCH FOUND] ONOS is active.
----
----"

sleep 5

echo "--------------------"
echo "Starting BMv2 switch"
echo "--------------------"

sudo "$HOME"/p4tools/bmv2/targets/simple_switch_grpc/simple_switch_grpc --device-id 1 -i 1@s1-eth2 --thrift-port 36869 -Lwarn --no-p4  -- --cpu-port 255 --grpc-server-addr 0.0.0.0:50001 > /dev/null &

sleep 5

echo "--------------------"
echo "Pushing netconf and host info to ONOS"
echo "--------------------"

netcfg="@$HOME/spid/netcfg.json"
host="@$HOME/spid/host.json"
sketches="@$HOME/spid/t_sketches_config.json"

curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -d "$netcfg" --user onos:rocks 'http://localhost:8181/onos/v1/network/configuration'

sleep 5

curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -d "$host" --user onos:rocks 'http://localhost:8181/onos/v1/hosts'

sleep 5

curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -d "$sketches" --user onos:rocks 'http://localhost:8181/onos/v1/flows'

sleep 5

echo "--------------------"
echo "Configuring P4 hash function polynomials"
echo "--------------------"

cd ~/spid/ || exit

./hash_config.sh

sleep 5

echo "--------------------" 
echo "Running tcpreplay"
echo "--------------------"

sudo tcpreplay -i s1-eth2 -K --pps=1000 "$@"

while :; do
    sleep 5
done