#!/bin/bash

KEYS_PREFIX=/ndn/keys
PRODUCER_ID=producer
ACCESS_CONTROLLER_ID=accesscontroller
GROUP_KEYS_DISTRIBUTOR_ID=groupkeysdistributor
CONSUMER1_ID=consumer1
CONSUMER2_ID=consumer2

ID_LIST="$PRODUCER_ID $CONSUMER1_ID $CONSUMER2_ID $ACCESS_CONTROLLER_ID $GROUP_KEYS_DISTRIBUTOR_ID"

for id in $ID_LIST
do
   # KSK Keys
   ndnsec-key-gen $KEYS_PREFIX/$id > /dev/null
   ndnsec-sign-req $KEYS_PREFIX/$id > ./config/${id}-ksk.cert
   ndnsec-cert-install -f ./config/${id}-ksk.cert
   ndnsec-list -kc | grep $KEYS_PREFIX/${id}/ksk | sed 's/\+->\* //' | sed 's/ *//' >> keys.txt

   # DSK Keys
   ndnsec-key-gen -d $KEYS_PREFIX/$id > /dev/null
   ndnsec-sign-req $KEYS_PREFIX/$id > ./config/${id}-dsk.cert
   ndnsec-cert-install -f ./config/${id}-dsk.cert
   ndnsec-list -kc | grep $KEYS_PREFIX/${id}/dsk | sed 's/\+->\* //' | sed 's/ *//' >> keys.txt
done
