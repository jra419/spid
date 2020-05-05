#!/bin/bash

echo "--------------------"
echo "Starting veth interfaces and cleaning up"
echo "--------------------"

sudo pkill -f simple_switch_grpc
sudo pkill -f flowstats_

sudo bash veth_teardown.sh
sudo bash veth_setup.sh

echo "--------------------"
echo "ML python REST script: Isolation Forest"
echo "--------------------"

python3 flowstats_forest_rest.py &

sleep 10

echo "--------------------"
echo "Starting ONOS"
echo "--------------------"

cd ~/onos/

sleep 5

export ONOS_APPS=drivers.bmv2,proxyarp,lldpprovider,hostprovider,fwd,gui2,p4flowstats.pipeconf,p4flowstats.flowstats

bazel run onos-local -- clean &

sleep 60

tail -f /tmp/onos-2.2.1-SNAPSHOT/onos.log | while read LOGLINE
do
   [[ "${LOGLINE}" == *"Application org.onosproject.routeradvertisement has been installed"* ]] && pkill -P $$ tail
done
echo "
----
----
[MATCH FOUND] ONOS is active.
----
----"

sleep 20

echo "--------------------"
echo "Starting BMv2 switch"
echo "--------------------"

sudo simple_switch_grpc --device-id 1 -i 1@s1-eth1 -i 2@s1-eth2 --thrift-port 36869 -Lwarn --no-p4 -- --cpu-port 255 --grpc-server-addr 0.0.0.0:50001 > /dev/null &

sleep 15

echo "--------------------"
echo "Pushing netconf and host info to ONOS"
echo "--------------------"

netcfg="@$HOME/spid/netcfg.json"
host1="@$HOME/spid/host1.json"
host2="@$HOME/spid/host2.json"

curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -d $netcfg --user onos:rocks 'http://192.168.70.134:8181/onos/v1/network/configuration' 

sleep 10

curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -d $host1 --user onos:rocks 'http://192.168.70.134:8181/onos/v1/hosts' 

sleep 5

curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -d $host2 --user onos:rocks 'http://192.168.70.134:8181/onos/v1/hosts' 

sleep 5

echo "--------------------"
echo "Configuring P4 hash function polynomials"
echo "--------------------"

cd ~/spid/

./runtime_cli_config_flowstats.sh

# echo "--------------------" 
# echo "Running tcpreplay: Training set"
# echo "--------------------"

# sudo tcpreplay -i s1-eth1 -K --limit=10000 --pps=100 $1

echo "--------------------" 
echo "Running tcpreplay: Test set"
echo "--------------------"

cd ~/Documents/

sudo tcpreplay -i s1-eth1 -K --limit=20000 --pps=100 $1

# echo "--------------------"
# echo "Clustering: K-Means"
# echo "--------------------"

# python3 flowstats_kmeans_silhouette.py flow-stats/threshold.csv

# echo "--------------------"
# echo "Outlier Detection: Isolation Forest"
# echo "--------------------"

# python3 flowstats_forest.py flow-stats/threshold.csv

