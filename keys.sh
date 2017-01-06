 ndnsec-key-gen -n /ndn/keys/trust > /dev/null
 ndnsec-sign-req /ndn/keys/trust > ./config/trust.cert 

ndnsec-key-gen -n /ndn/keys/producer > ./config/producer-unsigned.cert;
ndnsec-cert-install ./config/producer-unsigned.cert
ndnsec-cert-gen -s /ndn/keys/trust -N "Producer" -r ./config/producer-unsigned.cert > ./config/producer-ksk.cert
ndnsec-cert-install ./config/producer-ksk.cert
ndnsec-list -kc | grep /ndn/keys/producer/ksk | sed 's/\+->\* //' | sed 's/ *//' >> keys.txt
ndnsec-key-gen -d /ndn/keys/producer > ./config/producer-dsk.cert
ndnsec-cert-install -f ./config/producer-dsk.cert
ndnsec-list -kc | grep /ndn/keys/producer/dsk | sed 's/\+->\* //' | sed 's/ *//' >> keys.txt

ndnsec-key-gen -n /ndn/keys/consumer1 > ./config/consumer1-unsigned.cert
ndnsec-cert-gen -s /ndn/keys/trust -N "Consumer1" -r ./config/consumer1-unsigned.cert > ./config/consumer1-ksk.cert
ndnsec-cert-install ./config/consumer1-ksk.cert
ndnsec-list -kc | grep /ndn/keys/consumer1/ksk | sed 's/\+->\* //' | sed 's/ *//' >> keys.txt
ndnsec-key-gen -d /ndn/keys/consumer1 > ./config/consumer1-dsk.cert
ndnsec-cert-install -f ./config/consumer1-dsk.cert
ndnsec-list -kc | grep /ndn/keys/consumer1/dsk | sed 's/\+->\* //' | sed 's/ *//' >> keys.txt

ndnsec-key-gen -n /ndn/keys/consumer2 > ./config/consumer2-unsigned.cert
ndnsec-cert-gen -s /ndn/keys/trust -N "Consumer2" -r ./config/consumer2-unsigned.cert > ./config/consumer2-ksk.cert
ndnsec-cert-install ./config/consumer2-ksk.cert
ndnsec-list -kc | grep /ndn/keys/consumer2/ksk | sed 's/\+->\* //' | sed 's/ *//' >> keys.txt
ndnsec-key-gen -d /ndn/keys/consumer2 > ./config/consumer2-dsk.cert
ndnsec-cert-install -f ./config/consumer2-dsk.cert
ndnsec-list -kc | grep /ndn/keys/consumer2/dsk | sed 's/\+->\* //' | sed 's/ *//' >> keys.txt

ndnsec-key-gen -n /ndn/keys/accesscontroller > ./config/accesscontroller-unsigned.cert
ndnsec-cert-gen -s /ndn/keys/trust -N "Access Controller" -r ./config/accesscontroller-unsigned.cert > ./config/accesscontroller-ksk.cert
ndnsec-cert-install ./config/accesscontroller-ksk.cert
ndnsec-list -kc | grep /ndn/keys/accesscontroller/ksk | sed 's/\+->\* //' | sed 's/ *//' >> keys.txt
ndnsec-key-gen -d /ndn/keys/accesscontroller > ./config/accesscontroller-dsk.cert
ndnsec-cert-install -f ./config/accesscontroller-dsk.cert
ndnsec-list -kc | grep /ndn/keys/accesscontroller/dsk | sed 's/\+->\* //' | sed 's/ *//' >> keys.txt


ndnsec-key-gen -n /ndn/keys/groupkeysdistributor > ./config/groupkeysdistributor-unsigned.cert
ndnsec-cert-gen -s /ndn/keys/trust -N "groupkeysdistributor" -r ./config/groupkeysdistributor-unsigned.cert > ./config/groupkeysdistributor-ksk.cert
ndnsec-cert-install ./config/groupkeysdistributor-ksk.cert
ndnsec-list -kc | grep /ndn/keys/groupkeysdistributor/ksk | sed 's/\+->\* //' | sed 's/ *//' >> keys.txt
ndnsec-key-gen -d /ndn/keys/groupkeysdistributor > ./config/groupkeysdistributor-dsk.cert
ndnsec-cert-install -f ./config/groupkeysdistributor-dsk.cert
ndnsec-list -kc | grep /ndn/keys/groupkeysdistributor/dsk | sed 's/\+->\* //' | sed 's/ *//' >> keys.txt
