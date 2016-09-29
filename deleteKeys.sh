#!/bin/bash

PRODUCER_ID=/ndn/keys/producer
CONSUMER1_ID=/ndn/keys/consumer1
CONSUMER2_ID=/ndn/keys/consumer2
ACCESS_CONTROLLER_ID=/ndn/keys/accesscontroller
GROUP_KEYS_DISTRIBUTOR_ID=/ndn/keys/groupkeysdistributor

ID_LIST="$PRODUCER_ID $CONSUMER1_ID $CONSUMER2_ID $ACCESS_CONTROLLER_ID $GROUP_KEYS_DISTRIBUTOR_ID"

for id in $ID_LIST
do
   ndnsec-delete $id
done

rm ./keys.txt ./config/*.cert
