#include "e_macaroon.pb.h"

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
//#include <ndn-cxx/security/cryptopp.hpp>
#include <ndn-cxx/security/validator-config.hpp>
#include <ndn-cxx/util/time.hpp>
//#include "util/scheduler.hpp"
#include <ndn-cxx/util/scheduler.hpp>

#include <NDNMacaroon/macaroon.hpp>
#include <NDNMacaroon/macaroon-utils.hpp>

#include <boost/regex.hpp>
#include <stdlib.h>
#include <time.h>

#include <map>

const std::string KEYNAMES_FILENAME="./keys.txt";
const std::string DATANAME = "/example/producer/alice/hearbeat/";
const std::string NAME_KEY_GROUP = "/keys/group/Doctors";
const std::string NAME_KEY_DATA = "/keys/data/Doctors";

namespace ndn {
    namespace examples {
        class Consumer : noncopyable
        {
            public:
                Consumer() 
                : m_face(m_ioService) // Create face with io_service object
                , m_scheduler(m_ioService){
                    std::cout << "ENTRA" << std::endl;
                    loadKeyNames();
                    srand(std::time(NULL));
                    std::string value = to_string(rand());
                    std::string key_group = NAME_KEY_GROUP + "/" + value;
                    std::string key_data = NAME_KEY_DATA + "/" + value;
                    key_group_name = ndn::Name(key_group);
                    key_data_name = ndn::Name(key_data);
                }

                void
                run(){
                   
                    requestData();
                    //m_face.processEvents();
                    m_ioService.run();
                }

                // *******************************************************
                //  REQUESTS
                // *******************************************************

                void
                requestData(){
                    std::cout << "REQUEST DATA:  " << std::endl;
                    ndn::Interest interest = createInterest(DATANAME + "info", false);
                    m_face.expressInterest(interest,
                                            bind(&Consumer::receivedData, this, _1, _2),
                                            bind(&Consumer::onTimeout, this, _1, 1));
                }

                void
                requestKeyData(){
                    std::cout << "REQUEST DATA:  " << std::endl;
                    ndn::Interest interest = createInterest(DATANAME + "getKeyData", false);
                    m_face.expressInterest(interest,
                                            bind(&Consumer::receivedKeyData, this, _1, _2),
                                            bind(&Consumer::onTimeout, this, _1, 1));
                }

                void
                requestMacaroon(){
                    std::cout << "REQUEST MACAROON:  " << std::endl;
                    ndn::Interest interest = createInterest("/example/accesscontroller/getMacaroon/Doctors", false);
                    m_face.expressInterest(interest,
                                            bind(&Consumer::receivedMacaroon, this, _1, _2),
                                            bind(&Consumer::onTimeout, this, _1, 1));
                }

                ndn::Interest
                createInterest(std::string address, bool sign){
                    Name interestName(address);
                    std::cout << "Interest: " << interestName << std::endl;
                    std::cout << "---------------------------------------" << std::endl;

                    Interest interest(interestName);
                    interest.setInterestLifetime(time::milliseconds(5000));
                    interest.setMustBeFresh(true);
                    if(sign){
                        const std::string CONSUMER_KSK_NAME = m_princKeyNames[CONSUMER_KSK];
                        m_keyChain.sign(interest, m_keyChain.getDefaultCertificateNameForKey(ndn::Name(CONSUMER_KSK_NAME)));
                    }
                    return interest;
                }

                // ********************************************************
                // RESPONSES TO REQUESTS
                // ********************************************************

                void
                receivedData(const Interest& interest, const Data& data) {

                    if(data.getName()[-1].toUri() == "notFound"){
                        std::cout << "DATA FILE NOT FOUND" << std::endl;
                    }else{
                        std::cout << "ENCRYPTING DATA RECEIVED" << std::endl;
                        enc_data = std::string(data.getContent().value(), data.getContent().value() + data.getContent().value_size());
                        if(!decryptingData()){
                            requestKeyData();
                        } 
                    }
                }

                void
                receivedKeyData(const Interest& interest, const Data& data) {

                    if(data.getName()[-1].toUri() == "notEncrypted"){
                        keyDataNotEncrypted();
                    }else{
                        enc_key_data = std::string(data.getContent().value(), data.getContent().value() + data.getContent().value_size());
                        if(setKeyData()){
                            decryptingData();
                        }else{
                            requestMacaroon();
                        }
                    }
                }

                void
                receivedMacaroon(const Interest& interest, const Data& data) {
                    std::cout << "MACAROON RECEIVED ..." << std::endl;
                    macaroons::e_macaroon e_macaroon;
                    e_macaroon.ParseFromArray(data.getContent().value(), data.getContent().value_size());
                    if (e_macaroon.endorsements_size() > 0) {
                        std::set<std::string> valid_names;
                        std::string serializedMacaroon = e_macaroon.macaroon();
                        // get name of macaroon and add to valid_names
                        macaroon = make_shared<macaroons::NDNMacaroon>(serializedMacaroon);
                        valid_names.insert(macaroon->getLocation());

                        // extract locations of third parties and add them to valid_names
                        for (unsigned i = 1; i <= macaroon->getNumThirdPartyCaveats(); i++){
                            std::string group_keys_distributor;
                            ndn::ConstBufferPtr tp_id_sp;
                            macaroon->getThirdPartyCaveat(i, group_keys_distributor, &tp_id_sp);
                            valid_names.insert(group_keys_distributor);
                        }
                        fetchCertificate(e_macaroon, valid_names, 0);
                    }
                }

                bool
                decryptingData(){
                    //ndn::Name key_data_name(NAME_KEY_DATA);
                    if(!m_secTpmFile.doesKeyExistInTpm(key_data_name, KEY_CLASS_SYMMETRIC)){
                        return false;
                    }
                    std::cout << "---------------------------------------" << std::endl;
                    std::cout << "Decrypting data ..." << std::endl;
                    
                    ndn::ConstBufferPtr dec_message = m_secTpmFile.decryptInTpm((uint8_t*) enc_data.c_str(),
                                                                                enc_data.size(),
                                                                                key_data_name,
                                                                                true);
                    std::cout << "MESSAGE DESCRYPTING: " << std::endl;
                    std::cout << std::string(dec_message->buf(), dec_message->buf() + dec_message->size()) << std::endl;
                    return true;
                }

                void
                keyDataNotEncrypted(){
                    //ndn::Name key_group_name(NAME_KEY_GROUP);
                    if(!m_secTpmFile.doesKeyExistInTpm(key_group_name, KEY_CLASS_SYMMETRIC)){
                        requestMacaroon();
                    }else{
                        m_scheduler.scheduleEvent(time::seconds(2),
                                                bind(&Consumer::requestKeyData, this));
                    }
                }


                bool
                setKeyData(){
                    //ndn::Name key_group_name(NAME_KEY_GROUP);
                    //ndn::Name key_data_name(NAME_KEY_DATA);
                    std::cout << "---------------------------------------" << std::endl;
                    std::cout << "Decrypting key data ..." << std::endl;
                    if(!m_secTpmFile.doesKeyExistInTpm(key_group_name, KEY_CLASS_SYMMETRIC)){
                        return false;
                        std::cout << "Necesary key group ..." << std::endl;
                        std::cout << "---------------------------------------" << std::endl;
                    }

                    std::cout << "Encrypted key data: " << std::endl
                    << enc_key_data
                    <<std::endl;

                    ndn::ConstBufferPtr dec_key_data = m_secTpmFile.decryptInTpm((uint8_t*) enc_key_data.c_str(),
                                                                                enc_key_data.size(),
                                                                                key_group_name, 
                                                                                true);
                    std::string key_data = std::string(dec_key_data->buf(), dec_key_data->buf() + dec_key_data->size());
                    m_secTpmFile.setSymmetricKeyToTpm(key_data_name, (uint8_t*) key_data.c_str(), key_data.size());

                    std::cout << "Encrypted key data: " << std::endl
                    << key_data <<std::endl;
                    std::cout << "---------------------------------------" << std::endl;

                    return true;
                }

                void
                fetchCertificate(macaroons::e_macaroon& e_macaroon, std::set<std::string>& valid_names, const int index){
                    if (index < e_macaroon.endorsements_size()) {
                        std::cout << "----- fetchCertificate -----" << std::endl;
                        std::string name = e_macaroon.endorsements(index).name();
                        if (valid_names.find(name) != valid_names.end()) {
                            std::string certname = e_macaroon.endorsements(index).certname();
                            Interest interest = createInterest(certname , false);
                            m_face.expressInterest(interest,
                                                    bind(&Consumer::onEndorseCertificateInternal,
                                                    this, _1, _2, e_macaroon, valid_names, index),
                                                    bind(&Consumer::onEndorseCertificateInternalTimeout,
                                                    this, _1, e_macaroon, valid_names, index));
                        }
                        else
                            fetchCertificate(e_macaroon, valid_names, index + 1);
                    }
                    else {
                        processThirdPartyCaveats ();
                    }
                }

                void
                onEndorseCertificateInternal(const Interest& interest, Data& data, macaroons::e_macaroon& e_macaroon,
                                                std::set<std::string>& valid_names, unsigned index)
                {

                    std::string kind = e_macaroon.endorsements(index).kind();
                    std::string name = e_macaroon.endorsements(index).name();
                    std::string certName = e_macaroon.endorsements(index).certname();

                    ndn::Name keyName = ndn::IdentityCertificate::certificateNameToPublicKeyName(certName);
                    std::cout << "Adding to secureChannels: " << name << std::endl;
                    secureChannels[name] = keyName.toUri();
                    // now we add the key to key chain so we can use it to encrypt
                    std::cout << "dsk keyName: " << keyName << std::endl;

                    if (!m_keyChain.doesPublicKeyExist(keyName))
                    m_keyChain.addKey(keyName, ndn::IdentityCertificate(data).getPublicKeyInfo());

                    std::cout << "----------------------------------" << std::endl;

                    fetchCertificate(e_macaroon, valid_names, index + 1);
                }

                void processThirdPartyCaveats ()
                {
                    std::cout << "processThirdPartyCaveats ()" << std::endl;

                    for (unsigned i = 1; i <= macaroon->getNumThirdPartyCaveats(); i++){
                        std::cout << "*********************************************" << std::endl;
                        std::cout << "*** process third party" << std::endl;

                        std::string group_keys_distributor;
                        ndn::ConstBufferPtr tp_id_sp;
                        macaroon->getThirdPartyCaveat(i, group_keys_distributor, &tp_id_sp);

                        std::cout << "GROUP KEYS DISTRIBUTOR: " << group_keys_distributor << std::endl;

                        ndn::Name session_key_name(std::string("/session-key-consumer") + std::string("-") + std::to_string(i));
                        ndn::ConstBufferPtr enc_session_key = createSessionKey(group_keys_distributor, session_key_name);

                        Name interestName(group_keys_distributor);
                        interestName.append(ndn::name::Component(enc_session_key))
                                    .append(ndn::name::Component(*tp_id_sp))
                                    .append("Doctors")
                                    .append("V1");

                        Interest interest = createInterest(interestName.toUri(), true);

                        m_face.expressInterest(interest,
                                                bind(&Consumer::onThirdPartyData, this, _2, session_key_name),
                                                bind(&Consumer::onTimeout, this, _1, 1));

                    }// for
                }

                void
                onThirdPartyData(const Data& data, ndn::Name& session_key_name){

                    if (data.getName()[-2].toUri() == "authenticated") {
                        std::cout << "authenticated!" << std::endl;

                        ndn::ConstBufferPtr decrypted_content =
                        m_secTpmFile.decryptInTpm(data.getContent().value(),
                                                data.getContent().value_size(),
                                                session_key_name, /*symmetric*/ true);

                        std::string dm = std::string(decrypted_content->buf(), decrypted_content->buf() + decrypted_content->size());

                        macaroon->addDischargeAndPrepare(dm);
                        validateMacaroonAndDischargue();
                    }
                    else
                        std::cout << "NOT authenticated!" << std::endl;
                }

                void
                validateMacaroonAndDischargue(){

                    ndn::Name session_key_name(std::string("/session-key-consumer"));
                    ndn::ConstBufferPtr enc_session_key = createSessionKey(macaroon->getLocation(), session_key_name);

                    std::string serialized_macaroon = macaroon->serialize();
                    std::string dm = macaroon->getDischargeMacaroon(1);
                    ndn::ConstBufferPtr enc_dischargue = m_secTpmFile.encryptInTpm((uint8_t*) dm.c_str(),
                                                                                    dm.size(),
                                                                                    session_key_name,
                                                                                    true  /* symmetric */);
                    ndn::ConstBufferPtr enc_dataname = m_secTpmFile.encryptInTpm((uint8_t*) DATANAME.c_str(),
                                                                                DATANAME.size(),
                                                                                session_key_name,
                                                                                true  /* symmetric */);
                    setKeyGroup(dm);

                    Name interestName(macaroon->getLocation() + "/update_group_key");
                    interestName.append(ndn::name::Component(enc_session_key));
                    interestName.append(serialized_macaroon);
                    interestName.append(ndn::name::Component(enc_dischargue));
                    interestName.append(ndn::name::Component(enc_dataname));
                    interestName.append("Doctors");
                    interestName.append("V1");

                    Interest interest = createInterest(interestName.toUri(), true);

                    m_face.expressInterest(interest,
                                            bind(&Consumer::responseValidatedMacaroonAndDischargue, this,  _1, _2),
                                            bind(&Consumer::onTimeout, this, _1, 1));
                }

                void
                responseValidatedMacaroonAndDischargue(const Interest& interest, const Data& data) {
                    if (data.getName()[-1].toUri() == "authorized") {
                        if(enc_key_data == ""){
                            requestKeyData();
                        }else{
                            setKeyData();
                            decryptingData();
                        }
                    }else{
                        std::cout << "Macaroon not validated" << std::endl;
                    }
                }

                ndn::ConstBufferPtr
                createSessionKey(std::string name, ndn::Name session_key_name){
                    ndn::Name public_key_name(secureChannels[name]);
                    const unsigned SESSION_KEY_SIZE = 32; // is 32 bytes enough. Check it.
                    ndn::ConstBufferPtr enc_session_key = macaroons::generateSessionKey(public_key_name, session_key_name, SESSION_KEY_SIZE);
                    return enc_session_key;
                }

                void
                setKeyGroup(std::string dm){
                    shared_ptr<macaroons::NDNMacaroon> discharge = make_shared<macaroons::NDNMacaroon>(dm);
                    std::string key_group =  discharge->getSignature();
                    m_secTpmFile.setSymmetricKeyToTpm(key_group_name, (uint8_t*)key_group.c_str(), key_group.size());
                }


                void
                onTimeout(const Interest& interest, unsigned retries)
                {
                    retries--;
                    if (retries != 0)
                        //m_face.expressInterest(interest,
                        //                    bind(&Consumer::receivedData, this, _1, _2),
                        //                    bind(&Consumer::onTimeout, this, _1, 1));

                    std::cout << "Timeout " << " retries: " << retries << "  " << interest  << std::endl;
                } //onTimeout

                void
                onEndorseCertificateInternalTimeout(const Interest& interest, macaroons::e_macaroon& e_macaroon, std::set<std::string>& valid_names, unsigned index)
                {
                    std::cout << "Can't fetch certificate" <<  interest << std::endl;
                    fetchCertificate(e_macaroon, valid_names, index + 1);
                }


                void
                loadKeyNames()
                {
                    std::ifstream is(KEYNAMES_FILENAME.c_str());
                    std::string line;
                    if (is.is_open()) {

                        //Producer
                        std::getline(is, line);
                        std::getline(is, line);

                        //Consumer1
                        std::getline(is, line);
                        m_princKeyNames[CONSUMER_KSK] = line;
                        std::cout <<  " CONSUMER_KSK = " << m_princKeyNames[CONSUMER_KSK] << std::endl;

                        std::getline(is, line);
                        m_princKeyNames[CONSUMER_DSK] = line;
                        std::cout <<  " CONSUMER_DSK = " << m_princKeyNames[CONSUMER_DSK] << std::endl;

                        is.close();

                    }
                }

            private:
                enum princEnum_t {CONSUMER_KSK, CONSUMER_DSK};


                ndn::SecTpmFileEnc m_secTpmFile;
                
                // m_princKeyNames: principal keynames are extracted from KEYNAMES_FILENAME
                std::map<princEnum_t, std::string> m_princKeyNames;
                

                
                boost::asio::io_service m_ioService;
                Face m_face;
                Scheduler m_scheduler;
                KeyChain m_keyChain;
                ValidatorConfig m_validator;
                std::map<std::string, std::string> secureChannels;
                shared_ptr<macaroons::NDNMacaroon> macaroon;

                //dataEncrypted
                std::string enc_data;
                std::string enc_key_data;
                ndn::Name key_data_name;
                ndn::Name key_group_name;

        };//Consumer
    }//examples
}//ndn

int
main(int argc, char** argv)
{
    ndn::examples::Consumer consumer;
    try {
        consumer.run();
    }
    catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
    }
    return 0;
}