#include <ndn-cxx/security/validator-config.hpp>

#include <boost/regex.hpp>

#include <group.hpp>

const std::string KEYNAMES_FILENAME="./keys.txt";
const std::string VALIDATOR_FILENAME="./config/validation.conf";
const bool VALIDATED = true;
const bool NOT_VALIDATED = false;

namespace ndn {
    namespace examples {
        class GroupKeysDistributor : noncopyable
        {
            public:
                GroupKeysDistributor() {
                    loadKeyNames();
                    m_validator.load(VALIDATOR_FILENAME);
                    keyNameToUser[m_princKeyNames[ACCESS_CONTROLLER_KSK]] = "accesscontroller";
                    keyNameToUser[m_princKeyNames[CONSUMER1_KSK]] = "consumer1";
                    std::shared_ptr<Group> dptoRRHH = make_shared<Group>();
                    dptoRRHH->setName("dptoRRHH");
                    dptoRRHH->addMember(keyNameToUser[m_princKeyNames[CONSUMER1_KSK]]);
                    listGroups["dptoRRHH"] = dptoRRHH;
                }

                void
                run(){
                    m_face.setInterestFilter(GROUP_KEYS_DISTRIBUTOR_PREFIX,
                                        bind(&GroupKeysDistributor::onInterest, this, _1, _2, NOT_VALIDATED),
                                        RegisterPrefixSuccessCallback(),
                                        bind(&GroupKeysDistributor::onRegisterFailed, this, _1, _2));

                    m_face.setInterestFilter(m_gkdIdentity,
                                        bind(&GroupKeysDistributor::onKeyInterest, this, _1, _2),
                                        RegisterPrefixSuccessCallback(),
                                        bind(&GroupKeysDistributor::onRegisterFailed, this, _1, _2));

                    m_face.processEvents();
                }


                void
                onInterest(const InterestFilter& filter, const Interest& interest, bool validated)
                {
                    std::cout << ">> Interest: " << interest.getName() << std::endl;
                    if(!validated){
                        std::cout << "Validating interest ..." << std::endl;
                        m_validator.validate(interest,
                                            bind(&GroupKeysDistributor::onInterest, this, filter, interest, VALIDATED),
                                            bind(&GroupKeysDistributor::onValidationFailed, this, _1, _2));
                    }else{
                        std::cout << "Validated Interest ..." << std::endl;
                        std::string command = interest.getName().at(COMMAND_POS).toUri();
                        if ( command == "getDischargeMacaroon") {
                            proccessDischargeMacaroon(interest);
                        }else if(command == "setSharedSecret"){
                            setSharedSecret(interest);
                            ndn::Name dataName(interest.getName());
                            dataName.append("established");
                            sendData(dataName, NULL);
                        }
                    }
                } // onInterest


                void
                onKeyInterest(const InterestFilter& filter, const Interest& interest)
                {

                    Name keyName = ndn::Name(m_gkdIdentity + "/" + interest.getName().at(4).toUri());
                    std::cout << keyName << std::endl;
                    std::cout << "-----------------------------------------------" << std::endl;
                    std::cout << "<< I Certificate: " << interest.getName() << std::endl;

                    try {
                        shared_ptr<IdentityCertificate> cert =
                        m_keyChain.getCertificate(m_keyChain.getDefaultCertificateNameForKey(keyName));

                        std::cout << "<< Certificate: " << *cert << std::endl;
                        m_face.put(*cert);
                        std::cout << "---- SEND CERTIFICATE ----" << std::endl;
                    }
                    catch (const std::exception& ) {
                        std::cout << "The certificate: " << interest.getName()
                            << " does not exist"  << std::endl;
                    }
                    std::cout << "-----------------------------------------------" << std::endl;
                }

                void
                sendData(ndn::Name dataName, ndn::ConstBufferPtr enc_data){
                    shared_ptr<Data> data = make_shared<Data>();
                    data->setName(dataName);
                    if(enc_data != NULL){
                        data->setContent(enc_data);
                    }
                    data->setFreshnessPeriod(time::seconds(2));

                    m_keyChain.sign(*data, m_keyChain.getDefaultCertificateNameForKey(m_princKeyNames[GROUP_KEYS_DISTRIBUTOR_KSK]));
                    std::cout << "<< DATA: " << *data << std::endl;
                    m_face.put(*data);
                }

                void
                proccessDischargeMacaroon(const Interest& interest){

                    // Interest which requests dischargeMacaroon
                    std::string location = interest.getName().getPrefix(4).toUri();
                    ndn::Name session_key_ac_gkd(interest.getName()[HINT].toUri());
                    ndn::name::Component identifier = interest.getName().at(TPC_POS);
                    std::string nameGroup = interest.getName().at(GROUP_POS).toUri();
                    std::string userName = whoIsSignature(interest);
                    std::cout << "NAME=" << session_key_ac_gkd << std::endl;
                    std::cout << "LLOCATION="  << location << std::endl;

                    std::shared_ptr<Group> g = listGroups[nameGroup];
                    std::cout << "GROUP= "  << g->name << std::endl;
                    
                    // get session_key
                    ndn::Name session_key_name("session-key-consumer-gkd");
                    ndn::name::Component encrypted_session_key = interest.getName().at(SESSION_KEY_POS);
                    getSessionKeyFromInterest(encrypted_session_key, session_key_name);

                    ndn::ConstBufferPtr c =
                    m_secTpmFile.decryptInTpm(reinterpret_cast<const uint8_t*>(identifier.value()),
                                            identifier.value_size(), session_key_ac_gkd, true);

                    std::string caveat_keyPredicate = std::string(c->buf(), c->buf() + c->size());

                    std::cout << "caveat_keyPredicate:    "<< caveat_keyPredicate  << std::endl;
                    std::cout << "id plain: " << std::string(c->buf(), c->buf() + c->size()) << std::endl;
                    std::cout << "predicate: " << std::string(c->buf() + MACAROON_SUGGESTED_SECRET_LENGTH + 2, c->buf() + c->size())
                    << std::endl;

                    Name dataName(interest.getName());

                    bool authenticated = checkPredicate(caveat_keyPredicate, g, userName);
                    std::cout << "Authentication:  " << authenticated << std::endl;

                    if (authenticated) {
                        // create discharge macaroon
                        std::string serialize_disMacaroon =
                        g->getDischargueMacaroon(location,
                                                (uint8_t*)c->buf(),
                                                (uint8_t*)identifier.value(),
                                                identifier.value_size());
                        std::cout << "Serialize DM:   "  << serialize_disMacaroon  << std::endl;

                        ndn::ConstBufferPtr encrypted_serialized_disMacaroon =
                        m_secTpmFile.encryptInTpm((uint8_t*) serialize_disMacaroon.c_str(),
                                                    serialize_disMacaroon.size(),
                                                    session_key_name,
                                                    true);
                        dataName
                            .append("authenticated")
                            .appendVersion();
                        sendData(dataName, encrypted_serialized_disMacaroon);
                    }else{
                        dataName
                            .append("notAuthenticated") 
                            .appendVersion(); 
                        sendData(dataName, NULL);
                    }
                }//proccessDischargeMacaroon

                void
                getSessionKeyFromInterest(ndn::name::Component encrypted_session_key,
                                        const Name session_key_name)
                {
                    // Decrypt session_key sent by consummer, using Third Party private key
                    ndn::Name pub_key_name(m_princKeyNames[GROUP_KEYS_DISTRIBUTOR_DSK]);
                    ndn::ConstBufferPtr session_key_bits =
                    m_secTpmFile.decryptInTpm(encrypted_session_key.value(),
                                            encrypted_session_key.value_size(),
                                            pub_key_name, false);

                    // save session_key_bits with /session-key name inside m_secTpmFile
                    m_secTpmFile.setSymmetricKeyToTpm(session_key_name,
                                                    session_key_bits->buf(),
                                                    session_key_bits->size());

                    std::cout << "Session key name=" << session_key_name << " added to secTpmFile" << std::endl;
                }


                void
                setSharedSecret(const Interest& interest)
                {
                    //     0      1            2            3                       4
                    // /example/gkd/setSharedSecret/hint_shared_secret/encryptedSharedSecret

                    std::cout << "----------------------------------------" << std::endl;
                    std::cout << "Saving shared secret ..." << std::endl;

                    ndn::Name session_key_name(interest.getName()[3].toUri());
                    ndn::name::Component encrypted_session_key = interest.getName().at(4);
                    getSessionKeyFromInterest(encrypted_session_key, session_key_name);

                    std::cout << "----------------------------------------" << std::endl;

                }// onValidatedSetSharedSecret

                std::string
                whoIsSignature(const Interest& interest){
                    const Name& interestName = interest.getName();
                    Signature signature(interestName[signed_interest::POS_SIG_INFO].blockFromValue(),
                                        interestName[signed_interest::POS_SIG_VALUE].blockFromValue());

                    if (!signature.hasKeyLocator())
                        return "";

                    const KeyLocator& keyLocator = signature.getKeyLocator();

                    if (keyLocator.getType() != KeyLocator::KeyLocator_Name)
                        return "";

                    Name keyName = IdentityCertificate::certificateNameToPublicKeyName(keyLocator.getName());
                    std::cout << "keyName: " << keyName << std::endl;
                    return keyNameToUser[keyName.toUri()];


                }

                bool
                checkPredicate(const std::string& predicate, std::shared_ptr<Group> g, std::string userName){

                    if(userName == "")
                        return false;
                    // types of predicate: user==username group==groupName
                    std::cout << "PREDICATE: " << predicate << std::endl;
                    size_t posPred = predicate.find("::", MACAROON_SUGGESTED_SECRET_LENGTH);
                    size_t pos = predicate.find("==", MACAROON_SUGGESTED_SECRET_LENGTH);

                    std::string typePredicate = predicate.substr(MACAROON_SUGGESTED_SECRET_LENGTH+2, pos-posPred-2);
                    std::cout<< "typePredicate: " << typePredicate << std::endl;

                    if (typePredicate == "group"){
                        std::string groupName = predicate.substr(pos + 2);
                        std::cout << "groupName: " << groupName << std::endl;
                        if(g->name == groupName){
                            std::cout << "userName:" << userName << std::endl;
                            return g->isMember(userName);
                        }else{
                            return false;
                        }
                    }
                    else
                        return false;

                }// checkPredicate

                void
                onRegisterFailed(const Name& prefix, const std::string& reason)
                {
                    std::cerr << "ERROR: Failed to register prefix \""
                    << prefix << "\" in local hub's daemon (" << reason << ")"
                    << std::endl;
                    m_face.shutdown();
                }

                void
                onValidationFailed(const shared_ptr<const Interest>& interest, const std::string& failureInfo)
                {
                    std::cerr << "Not validated INTEREST " << interest->getName()
                    << ". The failure info: " << failureInfo << std::endl;
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

                        //consumer1
                        std::getline(is, line);
                        m_princKeyNames[CONSUMER1_KSK] = line;
                        std::cout <<  " CONSUMER1_KSK = " << m_princKeyNames[CONSUMER1_KSK] << std::endl;
                        std::getline(is, line);
                        m_princKeyNames[CONSUMER1_DSK] = line;
                        std::cout <<  " CONSUMER1_DSK = " << m_princKeyNames[CONSUMER1_DSK] << std::endl;
                        //Consumer2
                        std::getline(is, line);
                        std::getline(is, line);

                        //access controller
                        std::getline(is, line);
                        m_princKeyNames[ACCESS_CONTROLLER_KSK] = line;
                        std::cout <<  " ACCESS_CONTROLLER_KSK = " << m_princKeyNames[ACCESS_CONTROLLER_KSK] << std::endl;
                        std::getline(is, line);
                        m_princKeyNames[ACCESS_CONTROLLER_DSK] = line;
                        std::cout <<  " ACCESS_CONTROLLER_DSK = " << m_princKeyNames[ACCESS_CONTROLLER_DSK] << std::endl;

                        //Group Keys Distributor
                        std::getline(is, line);
                        m_princKeyNames[GROUP_KEYS_DISTRIBUTOR_KSK] = line;
                        std::cout <<  " GROUP_KEYS_DISTRIBUTOR_KSK = " << m_princKeyNames[GROUP_KEYS_DISTRIBUTOR_KSK] << std::endl;
                        std::getline(is, line);
                        m_princKeyNames[GROUP_KEYS_DISTRIBUTOR_DSK] = line;
                        std::cout <<  " GROUP_KEYS_DISTRIBUTOR_DSK = " << m_princKeyNames[GROUP_KEYS_DISTRIBUTOR_DSK] << std::endl;

                        is.close();

                        boost::regex identity("(.*)/dsk-(.*)");
                        boost::cmatch matches;

                        if (boost::regex_match(line.c_str(), matches, identity)) {
                            m_gkdIdentity = matches[1];
                        }
                        std::cout << "Group Keys Distributor identity = " << m_gkdIdentity << std::endl;
                    }
                }


            private:
                const std::string GROUP_KEYS_DISTRIBUTOR_PREFIX = "/example/groupKeysDistributor";

                //example/groupKeysDistributor/commando/hint/key_session/tpc/group/Vgroup
                enum {
                    // 0 --> /example
                    // 1 --> /thirdParty
                    COMMAND_POS     = 2,
                    HINT            = 3,
                    SESSION_KEY_POS = 4,
                    TPC_POS         = 5,
                    GROUP_POS       = 6,
                    VGROUP_POS      = 7
                };

                enum princEnum_t {CONSUMER1_KSK, CONSUMER1_DSK, ACCESS_CONTROLLER_KSK, ACCESS_CONTROLLER_DSK, GROUP_KEYS_DISTRIBUTOR_KSK, GROUP_KEYS_DISTRIBUTOR_DSK};

                // m_producerIdentity is extracted from KEYNAMES_FILENAME
                std::string m_gkdIdentity;
                // m_princKeyNames: principal keynames are extracted from KEYNAMES_FILENAME
                std::map<princEnum_t, std::string> m_princKeyNames;

                std::map<std::string, std::string> keyNameToUser;
                std::map<std::string, std::shared_ptr<Group> > listGroups;

                Face m_face;
                KeyChain m_keyChain;
                ValidatorConfig m_validator;
                ndn::SecTpmFileEnc m_secTpmFile;

        };
    } //examples
} //ndn

int
main(int argc, char** argv)
{
  ndn::examples::GroupKeysDistributor gkd;
  try {
    gkd.run();
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
  }
  return 0;
}