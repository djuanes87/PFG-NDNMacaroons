#include <ndn-cxx/security/key-chain.hpp>

#include <ndn-cxx/security/validator-config.hpp>

#include "sec-tpm-file-enc.hpp"

const std::string KEYNAMES_FILENAME="./keys.txt";
const std::string VALIDATOR_FILENAME="./config/validation-producer.conf";
const std::string NAME_KEY_GROUP = "/keys/group/Doctors";
const std::string NAME_KEY_DATA = "/keys/data/Doctors";


namespace ndn {
    namespace examples {
        class Producer: noncopyable
        {
            public:
                Producer() {
                    srand(std::time(NULL));
                    std::string value = to_string(rand());
                    std::string key_group = NAME_KEY_GROUP + "/" + value;
                    std::string key_data = NAME_KEY_DATA + "/" + value;
                    key_group_name = ndn::Name(key_group);
                    key_data_name = ndn::Name(key_data);
                    std::cout << "Key Group Name: " << key_group_name <<std::endl;
                    std::cout << "Key Group Name: " << key_data_name <<std::endl;
                    createKeyData();
                    encryptData();
                    enc_files["info"] = enc_message;
                    loadKeyNames();
                    m_validator.load(VALIDATOR_FILENAME);
                }

                void
                run(){
                    // -- ++ -- Direccion donde pedir datos -- ++ --
                    m_face.setInterestFilter(PRODUCER_PREFIX,
                                            bind(&Producer::onInterest, this, _1, _2),
                                            RegisterPrefixSuccessCallback(),
                                            bind(&Producer::onRegisterFailed, this, _1, _2));
                    m_face.processEvents();
                }

                void
                onInterest(const InterestFilter& filter, const Interest& interest)
                {
                    std::cout << "Request Interest:  " << interest.getName() << std::endl;
                    Name interestName = interest.getName();
                    //Interest Name: /example/producer/alice/hearbeat/<command or Data>/...
                    std::string command = interestName.at(COMMAND_POS).toUri();
                    std::cout << "Request operation: " << command <<std::endl;

                    if(command == "getKeyData"){
                        getKeyData(interest);
                    }else if(command == "setKeyGroup"){
                        m_validator.validate(interest, 
                                            bind(&Producer::setKeyGroup, this, interest),
                                            bind(&Producer::onValidationFailed, this, _1, _2));
                        //setKeyGroup(interest);
                    }else{
                        sendEncryptedData(interest);
                    }
                }

                void
                sendData(ndn::Name dataName, ndn::ConstBufferPtr enc_data){
                    std::cout << "------------------------------------" << std::endl;
                    shared_ptr<Data> data = make_shared<Data>();
                    data->setName(dataName);
                    if(enc_data != NULL){
                        data->setContent(enc_data);
                    }
                    data->setFreshnessPeriod(time::seconds(2));
                    m_keyChain.sign(*data, m_keyChain.getDefaultCertificateNameForKey(m_princKeyNames[PRODUCER_KSK]));
                    std::cout << ">> SEND DATA: " << std::endl << *data << std::endl;
                    std::cout << "------------------------------------" << std::endl;
                    m_face.put(*data);
                }

                void
                getKeyData(const Interest& interest){
                    Name dataName = interest.getName();

                    if (!m_secTpmFile.doesKeyExistInTpm(key_group_name, KEY_CLASS_SYMMETRIC)){
                        dataName.append("notEncrypted");
                        sendData(dataName, NULL);
                    }else{
                        dataName.append("keyDataEncrypted");
                        sendData(dataName, enc_key_data);
                    }
                }

                void
                setKeyGroup(const Interest& interest){
                    Name dataName = interest.getName();

                    if (!m_secTpmFile.doesKeyExistInTpm(key_group_name, KEY_CLASS_SYMMETRIC)){
                        storeKeyGroup(interest.getName().at(KEY_GROUP_POS));
                        encryptKeyData();
                        dataName.append("sucefull");
                    }else{
                        dataName.append("alreadyExist");
                    }
                    sendData(dataName, NULL);
                }

                void
                sendEncryptedData(const Interest& interest){
                    std::map<std::string, ndn::ConstBufferPtr>::iterator it;

                    Name dataName = interest.getName();
                    ndn::ConstBufferPtr enc_data;
                    std::string name_data = interest.getName().at(COMMAND_POS).toUri();
                    it = enc_files.find(name_data);
                    if(it == enc_files.end()){
                        dataName.append("notFound");
                       sendData(dataName, NULL);
                    }else{
                        enc_data = enc_files[name_data];
                        dataName.append("encryptedData");
                        sendData(dataName, enc_data);
                    }

                }

                void storeKeyGroup(ndn::name::Component enc_key_group) {

                    ndn::Name public_key_name(m_princKeyNames[PRODUCER_DSK]);
                    ndn::ConstBufferPtr decrypted_key_group = m_secTpmFile.decryptInTpm(enc_key_group.value(),
                                                                                        enc_key_group.value_size(),
                                                                                        public_key_name,
                                                                                        false);
                    std::string key_group = std::string(decrypted_key_group->buf(),
                                                        decrypted_key_group->buf() + decrypted_key_group->size());

                    std::cout << "KEY GROUP:   " << key_group << std::endl;

                    //Save key group
                    m_secTpmFile.setSymmetricKeyToTpm(key_group_name, (uint8_t*) key_group.c_str(), key_group.size());
                }


                void
                onRegisterFailed(const Name& prefix, const std::string& reason){
                    std::cerr << "ERROR: Failed to register prefix \""
                    << prefix << "\" in local hub's daemon (" << reason << ")"
                    << std::endl;
                    m_face.shutdown();
                }

                void
                encryptKeyData(){ 
                    std::cout << "-----------------------------------" << std::endl;
                    std::cout << "Encrypting key Data: " << std::endl;

                    std::string keyData;
                    m_secTpmFile.getSymmetricKeyFromTpm(key_data_name, keyData);
                    std::cout << "Key data: " << keyData << std::endl;

                    enc_key_data = m_secTpmFile.encryptInTpm((uint8_t*)keyData.c_str(),
                                                        keyData.size(), key_group_name, true);

                    std::cout << "Encrypted key data: " << std::endl
                    << std::string(enc_key_data->buf(), enc_key_data->buf() + enc_key_data->size())
                    <<std::endl;

                    std::cout << "-----------------------------------" << std::endl;
                }

                void
                encryptData(){ 
                    std::cout << "-----------------------------------" << std::endl;
                    std::string message = "This message is the data";
                    std::cout << "Encrypting this message with data key: " << std::endl
                    << message << std::endl;

                    //ndn::Name key_data_name(NAME_KEY_DATA);
                    enc_message = m_secTpmFile.encryptInTpm((uint8_t*) message.c_str(),
                                                        message.size(), key_data_name, true);

                    std::cout << "Encrypted message: " << std::endl
                    << std::string(enc_message->buf(), enc_message->buf() + enc_message->size())
                    <<std::endl;

                    std::cout << "-----------------------------------" << std::endl;
                }

                void
                createKeyData(){
                    std::cout << "-----------------------------------" << std::endl;
                    std::cout << "Generating symmetric key for data ..." << std::endl;
                    
                    ndn::AesKeyParams aesKeyParams;
                    m_secTpmFile.generateSymmetricKeyInTpm(key_data_name, aesKeyParams);

                    std::cout << "Symmetric key generated ..." << std::endl; 
                    std::cout << "-----------------------------------" << std::endl;
                }

                void
                onValidationFailed(const shared_ptr<const Interest>& interest, const std::string& failureInfo)
                {
                    std::cerr << "Not validated data: " << interest->getName()
                    << ". The failure info: " << failureInfo << std::endl;
                }



                void
                loadKeyNames(){
                    std::ifstream is(KEYNAMES_FILENAME.c_str());
                    std::string line;
                    if (is.is_open()) {
                        std::getline(is, line);
                        m_princKeyNames[PRODUCER_KSK] = line;
                        std::cout <<  " PRODUCER_KSK = " << m_princKeyNames[PRODUCER_KSK] << std::endl;

                        std::getline(is, line);
                        m_princKeyNames[PRODUCER_DSK] = line;
                        std::cout <<  " PRODUCER_DSK = " << m_princKeyNames[PRODUCER_DSK] << std::endl;

                        is.close();
                    }
                }



            private:

                const std::string PRODUCER_PREFIX = "/example/producer/alice/hearbeat";
                enum {
                    // 0  --> /example
                    // 1  --> /producer
                    // 2  --> /alice
                    // 3  --> /hearbeat
                    COMMAND_POS         = 4, // Position of command in name: getMacaroon, deposit, withdraw
                    KEY_GROUP_POS       = 5, // Position of macaroon in name.

                    // Discharge i is in MACAROON_POS + i ...
                    INTEREST_SIG_VALUE  = -1,
                    INTEREST_SIG_INFO   = -2
                };
                enum princEnum_t {PRODUCER_KSK, PRODUCER_DSK};
                ndn::SecTpmFileEnc m_secTpmFile;
                // m_princKeyNames: principal keynames are extracted from KEYNAMES_FILENAME
                std::map<princEnum_t, std::string> m_princKeyNames;

                std::map<std::string, ndn::ConstBufferPtr> enc_files;
                ndn::ConstBufferPtr enc_message;
                ndn::ConstBufferPtr enc_key_data;

                Face m_face;
                KeyChain m_keyChain;
                ValidatorConfig m_validator;

                ndn::Name key_data_name;
                ndn::Name key_group_name;



        };//Producer
    }//examples
}//ndn

int
main(int argc, char** argv)
{
    ndn::examples::Producer producer;
    try {
        producer.run();
    }
    catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
    }
}
  