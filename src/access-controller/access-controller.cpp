#include "e_macaroon.pb.h"

#include <ndn-cxx/security/validator-config.hpp>

#include <manages-group.hpp>

#include <boost/regex.hpp>


const unsigned NUM_RETRIES = 1;

const std::string KEYNAMES_FILENAME="./keys.txt";
const std::string VALIDATOR_FILENAME="./config/validation-ac.conf";
const bool VALIDATED = true;
const bool NOT_VALIDATED = false;


namespace ndn {
    namespace examples {
        class AccessController : noncopyable
        {
            public:
            	AccessController() {
            		loadKeyNames();
            		m_validator.load(VALIDATOR_FILENAME);
                    sharedSecret();
                    std::shared_ptr<ManagesGroup> dptoRRHH = make_shared<ManagesGroup>();
                    dptoRRHH->setArgs("dptoRRHH", "/example/producer/dptoRRHH/contracts",
                                    ACCESS_CONTROLLER_PREFIX, "/example/groupKeysDistributor",
                                    HINT_SHARED_KEY_GKD);
                    dptoRRHH->addThirdPartyCaveat();
                    std::string kn = m_princKeyNames[ACCESS_CONTROLLER_DSK];
                    std::shared_ptr<ndn::IdentityCertificate> cert = m_keyChain.getCertificate(m_keyChain.getDefaultCertificateNameForKey(ndn::Name(kn)));
                    dptoRRHH->addEndorsement("dsk", kn, ACCESS_CONTROLLER_PREFIX, cert, 0);
                    kn = m_princKeyNames[GROUP_KEYS_DISTRIBUTOR_DSK];
                    cert = m_keyChain.getCertificate(m_keyChain.getDefaultCertificateNameForKey(ndn::Name(kn)));
                    dptoRRHH->addEndorsement("dsk", kn, "/example/groupKeysDistributor/getDischargeMacaroon/" + HINT_SHARED_KEY_GKD, cert, 1);

                    listGroups["dptoRRHH"] = dptoRRHH;

            	}

            	void
                run(){
                    m_face.setInterestFilter(ACCESS_CONTROLLER_PREFIX,
                                          bind(&AccessController::onInterest, this, _1, _2),
                                          RegisterPrefixSuccessCallback(),
                                          bind(&AccessController::onRegisterFailed, this, _1, _2));
                    m_face.setInterestFilter(m_acIdentity,
                                          bind(&AccessController::onKeyInterest, this, _1, _2),
                                          RegisterPrefixSuccessCallback(),
                                          bind(&AccessController::onRegisterFailed, this, _1, _2));

                    m_face.processEvents();
                }
                                void
                onInterest(const InterestFilter& filter, const Interest& interest)
                {
                	std::cout << "---------------------------------------------" << std::endl;
                    std::cout << "Interest received: " << interest.getName().size() << interest.getName().toUri() << std::endl;
                    
                    std::string command = interest.getName().at(COMMAND_POS).toUri();
                    std::cout << "Request Operation: " << command << std::endl;

                    if(command == "getMacaroon"){
                    	getMacaroon(interest);
                    }else if(command == "updateGroupKey"){
						m_validator.validate(interest, 
											bind(&AccessController::updateGroupKey, this, interest),
                                            bind(&AccessController::onValidationInterestFailed, this, _1, _2));
                    }
                }

                void
                onKeyInterest(const InterestFilter& filter, const Interest& interest)
                {

                    Name keyName = ndn::Name(m_acIdentity + "/" + interest.getName().at(4).toUri());
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
                getMacaroon(const Interest& interest){
                	Name dataName = interest.getName();
                	ndn::OBufferStream os;
                	std::shared_ptr<ManagesGroup> g = getGroup(interest.getName().at(COMMAND_POS+1).toUri());
                	if(g == NULL){
                		dataName
                    	    .append("MacaroonGroupNotFound")
                    	    .appendVersion();
                    	sendData(dataName, NULL);
                	}else{
                    	macaroons::e_macaroon  e = g->getMacaroon();
                    	e.SerializeToOstream(&os);
                    	dataName
                    	    .append("result")
                    	    .appendVersion();
                    	sendData(dataName, os.buf());
                    }
                }

                void
                updateGroupKey(const Interest& interest){
                	Name dataName = interest.getName();
                	std::shared_ptr<ManagesGroup> g = getGroup(interest.getName().at(GROUP_POS).toUri());
                	if(g == NULL){
                		dataName
                    	    .append("groupNotFound")
                    	    .appendVersion();
                    	sendData(dataName, NULL);
                	}else{
                   		ndn::Name session_key_name("/session-key-ac-consumer");
                    	ndn::name::Component encrypted_session_key = interest.getName().at(SESSION_KEY_POS);
                    	getSessionKeyFromInterest(encrypted_session_key, session_key_name);

                    	std::string serializated_macaroon = interest.getName().at(MACAROON_POS).toUri();
                    	ndn::name::Component encrypted_dm = interest.getName().at(DM_POS);

                    	if(!g->verificateMacaroon(serializated_macaroon, encrypted_dm, session_key_name)){
                    	    ndn::Name public_key_name(m_princKeyNames[PRODUCER_DSK]);
                    	    ndn::ConstBufferPtr enc_key_group = g->extractKeyGroup(encrypted_dm, m_princKeyNames[PRODUCER_DSK], session_key_name);
                    	    ndn::name::Component encrypted_dataname = interest.getName().at(DATANAME_POS);
                    	    ndn::ConstBufferPtr decrypted_dataname = m_secTpmFile.decryptInTpm(encrypted_dataname.value(),
                  		                                                                    encrypted_dataname.value_size(),
                    	                                                                    session_key_name,
                                                                                        /*symmetric*/ true);
                    	    std::string dataname_scope = std::string(decrypted_dataname->buf(), decrypted_dataname->buf() + decrypted_dataname->size());
                    	    if(g->checkScope(dataname_scope)){
                    	        dataName.append("authorized");
                    	        sendData(dataName, NULL);
                    	        sendKeyGroupProducer(dataname_scope, enc_key_group, ndn::Name(interest.getName()));
                    	    }else{
                    	        dataName.append("non_authorized")
                    	                .appendVersion();
                    	        sendData(dataName, NULL);
                    	    }
                        }
                    }
                }

                void
                sharedSecret() {

                    ndn::Name session_key_name(HINT_SHARED_KEY_GKD);
                    const unsigned SESSION_KEY_SIZE = 32; // is 32 bytes enough. Check it.
                    // public key of third party
                    const std::string GROUP_KEYS_DISTRIBUTOR_DSK_NAME = m_princKeyNames[GROUP_KEYS_DISTRIBUTOR_DSK];
                    ndn::Name public_key_name(GROUP_KEYS_DISTRIBUTOR_DSK_NAME);
                    ndn::ConstBufferPtr enc_session_key =
                    macaroons::generateSessionKey(public_key_name, session_key_name, SESSION_KEY_SIZE);

                    //     0     1            2        3     4
                    // /example/gkd/setSharedSecret/id/encryptedSharedSecret
                    Name interestName("/example/groupKeysDistributor/setSharedSecret");
                    interestName.append(HINT_SHARED_KEY_GKD);
                    // append encrypted session key to interest name
                    interestName.append(ndn::name::Component(enc_session_key));
                    Interest interest = createInterest(interestName.toUri(), true); 

                    m_face.expressInterest(interest,
                                        bind(&AccessController::onSetSharedSecretData, this, _1, _2, NOT_VALIDATED),
                                        bind(&AccessController::onTimeoutSharedSecret, this, _1, 1));
                }

                void
                onSetSharedSecretData(const Interest& interest, const Data& data, bool validated)
                {
                    if(!validated){
                        m_validator.validate(data, 
                        					bind(&AccessController::onSetSharedSecretData, this, interest, data, VALIDATED),
                                            bind(&AccessController::onValidationDataFailed, this, _1, _2));
                    }else{
                        std::cout << "setSharedSecret done" << std::endl;
                        std::cout << "Validated data: " << data.getName() << std::endl;
                    }
                }// onData

                void sendKeyGroupProducer(ndn::Name interestName, ndn::ConstBufferPtr enc_key_group, ndn::Name dataname_consumer){
                    std::cout << "---------------------------------------------" << std::endl;
                    std::cout << "Establishing group password" << std::endl;

                    interestName.append("setKeyGroup");
                    interestName.append(ndn::Name::Component(enc_key_group));
                    Interest interest = createInterest(interestName.toUri(), true);
                    m_face.expressInterest(interest,
                                        bind(&AccessController::establisedKeyGroup, this, _1, _2, dataname_consumer, NOT_VALIDATED),
                                        bind(&AccessController::onTimeout, this, _1, dataname_consumer, 1));

                    std::cout << "---------------------------------------------" << std::endl;
                }

                void
                establisedKeyGroup(const Interest& interest, const Data& data, ndn::Name dataName ,bool validated )
                {
                    if(!validated){
                        m_validator.validate(data, 
                        					bind(&AccessController::establisedKeyGroup, this, interest, data, dataName, VALIDATED),
                                            bind(&AccessController::onValidationDataFailed, this, _1, _2));
                    }else{
                    	std::string result = data.getName()[RESULT_OPERATION].toUri();
                    	std::cout << "---------------------------------------------" << std::endl;
                    	if(result == "sucefull"){
							std::cout << "Established group password in Producer" << std::endl;
                    	}else if(result == "alreadyExist"){
							std::cout << "The group key already exists" << std::endl;
						}
                    	std::cout << "---------------------------------------------" << std::endl;
                    }
                }// onData

                void
                getSessionKeyFromInterest(ndn::name::Component encrypted_session_key,
                                        const Name session_key_name)
                {
					std::cout << "------------------------------------" <<  std::endl;
                    std::cout << "getSessionKeyFromInterest" <<  std::endl;

                    // Decrypt session_key sent by consummer, using Third Party private key
                    ndn::Name pub_key_name(m_princKeyNames[ACCESS_CONTROLLER_DSK]);
                    ndn::ConstBufferPtr session_key_bits =
                    m_secTpmFile.decryptInTpm(encrypted_session_key.value(),
                                            encrypted_session_key.value_size(),
                                            pub_key_name, false);

                    // save session_key_bits with /session-key name inside m_secTpmFile
                    m_secTpmFile.setSymmetricKeyToTpm(session_key_name,
                                                    session_key_bits->buf(),
                                                    session_key_bits->size());

                    std::cout << "Session key name=" << session_key_name << " added to secTpmFile" << std::endl;
                    std::cout << "------------------------------------" <<  std::endl;

                } // getSessionKeyFromInterest

                std::shared_ptr<ManagesGroup>
                getGroup(std::string groupName){
                	std::map<std::string, std::shared_ptr<ManagesGroup>>::iterator it;
  					it = listGroups.find(groupName);
  					if (it != listGroups.end()){
    					return listGroups[groupName];
  					}
  					return NULL;
  				}

                ndn::Interest
                createInterest(std::string address, bool sign){
                    Name interestName(address);
                    std::cout << "Interest: " << interestName << std::endl;
                    std::cout << "---------------------------------------" << std::endl;

                    Interest interest(interestName);
                    interest.setInterestLifetime(time::milliseconds(1000));
                    interest.setMustBeFresh(true);
                    if(sign){
                        const std::string ACCESS_CONTROLLER_KSK_NAME = m_princKeyNames[ACCESS_CONTROLLER_KSK];
                        m_keyChain.sign(interest, m_keyChain.getDefaultCertificateNameForKey(ndn::Name(ACCESS_CONTROLLER_KSK_NAME)));
                    }
                    return interest;
                }

                void 
                sendData(ndn::Name dataName, shared_ptr<Buffer> content){
                	std::cout << "----------------------------------------------" << std::endl;
                    shared_ptr<Data> data = make_shared<Data>();
                    data->setName(dataName);
                    data->setFreshnessPeriod(time::seconds(0));
                    if(content != NULL)
                        data->setContent(content);

                    const std::string ACCESS_CONTROLLER_KSK_NAME = m_princKeyNames[ACCESS_CONTROLLER_KSK];
                    m_keyChain.sign(*data, m_keyChain.getDefaultCertificateNameForKey(ACCESS_CONTROLLER_KSK_NAME));

                    std::cout << *data << std::endl;
                    std::cout << "----------------------------------------------" << std::endl;

                    m_face.put(*data);
                }

                void
                onRegisterFailed(const Name& prefix, const std::string& reason)
                {
                    std::cerr << "ERROR: Failed to register prefix \""
                    << prefix << "\" in local hub's daemon (" << reason << ")"
                    << std::endl;
                    m_face.shutdown();
                }

                void
                onValidationDataFailed(const shared_ptr<const Data>& data, const std::string& failureInfo)
                {
                    std::cerr << "Not validated data: " << data->getName()
                    << ". The failure info: " << failureInfo << std::endl;
                }

                void
                onValidationInterestFailed(const shared_ptr<const Interest>& interest, const std::string& failureInfo)
                {
                    std::cerr << "Not validated data: " << interest->getName()
                    << ". The failure info: " << failureInfo << std::endl;
                }

                void
                onTimeoutSharedSecret(const Interest& interest, unsigned retries)
                {
                    retries--;
                    if (retries != 0)
                    m_face.expressInterest(interest,
                                    bind(&AccessController::onSetSharedSecretData, this,  _1, _2, NOT_VALIDATED),
                                    bind(&AccessController::onTimeoutSharedSecret, this, _1, retries));

                    std::cout << "Timeout " << " retries: " << retries << "  " << interest  << std::endl;
                }

                void
                onTimeout(const Interest& interest, ndn::Name dataname, unsigned retries)
                {
                    retries--;
                    if (retries != 0)
                        m_face.expressInterest(interest,
                                            bind(&AccessController::establisedKeyGroup, this, _1, _2, dataname, NOT_VALIDATED),
                                            bind(&AccessController::onTimeout, this, _1, dataname, 1));

                    std::cout << "Timeout " << " retries: " << retries << "  " << interest  << std::endl;
                } //onTimeout

            	void
                loadKeyNames()
                {
                    std::ifstream is(KEYNAMES_FILENAME.c_str());
                    std::string line;
                    if (is.is_open()) {
                        //Producer
                        std::getline(is, line);
                        m_princKeyNames[PRODUCER_KSK] = line;
                        std::cout <<  " PRODUCER_KSK = " << m_princKeyNames[PRODUCER_KSK] << std::endl;
                        std::getline(is, line);
                        m_princKeyNames[PRODUCER_DSK] = line;
                        std::cout <<  " PRODUCER_DSK= " << m_princKeyNames[PRODUCER_DSK] << std::endl;

                        //consumer1
                        std::getline(is, line);
                        std::getline(is, line);
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

                        boost::regex identity("(.*)/dsk-(.*)");
                        boost::cmatch matches;
                        if (boost::regex_match(line.c_str(), matches, identity)) {
                            m_acIdentity = matches[1];
                            m_identity = ndn::Name(m_acIdentity);
                        }

                        //Group Keys Distributor
                        std::getline(is, line);
                        m_princKeyNames[GROUP_KEYS_DISTRIBUTOR_KSK] = line;
                        std::cout <<  " GROUP_KEYS_DISTRIBUTOR_KSK = " << m_princKeyNames[GROUP_KEYS_DISTRIBUTOR_KSK] << std::endl;
                        std::getline(is, line);
                        m_princKeyNames[GROUP_KEYS_DISTRIBUTOR_DSK] = line;
                        std::cout <<  " GROUP_KEYS_DISTRIBUTOR_DSK = " << m_princKeyNames[GROUP_KEYS_DISTRIBUTOR_DSK] << std::endl;

                        is.close();

                        std::cout << " Access Controller identity = " << m_acIdentity << std::endl;
                    }
                }

            private:
                std::string ACCESS_CONTROLLER_PREFIX = "/example/accesscontroller";
                std::string HINT_SHARED_KEY_GKD = "code1234";
                // Interest Name: /example/accesscontroller/<command>/<sessionKey>/<macaroon>/<dischargeMacaroon>/<dataname>/<Group>/<Version>

                enum {
                    // 0  --> /example
                    // 1  --> /producer
                    COMMAND_POS         = 2, // Position of command in name: getMacaroon, deposit, withdraw
                    SESSION_KEY_POS     = 3, // Position session Key
                    MACAROON_POS        = 4, // Position of macaroon in name.
                    DM_POS        		= 5, // Position of discharge macaroon in name.
                    DATANAME_POS        = 6, // Position of dataname in name.
                    GROUP_POS        	= 7, // Position of group in name.

                    // Discharge i is in MACAROON_POS + i ...
                    INTEREST_SIG_VALUE  = -1,
                    INTEREST_SIG_INFO   = -2,


                    RESULT_OPERATION	= -1
                };

                enum princEnum_t {PRODUCER_KSK, PRODUCER_DSK,
                                GROUP_KEYS_DISTRIBUTOR_KSK, GROUP_KEYS_DISTRIBUTOR_DSK,
                                ACCESS_CONTROLLER_KSK, ACCESS_CONTROLLER_DSK};

                Face m_face;
                KeyChain m_keyChain;
                ValidatorConfig m_validator;
                ndn::SecTpmFileEnc m_secTpmFile;

                // m_accessControllerIdentity is extracted from KEYNAMES_FILENAME
                std::string m_acIdentity;
                ndn::Name m_identity;
                // m_princKeyNames: principal keynames are extracted from KEYNAMES_FILENAME
                std::map<princEnum_t, std::string> m_princKeyNames;

                std::map<std::string, std::shared_ptr<ManagesGroup> > listGroups;

        };
    } //examples
} //ndn

int
main(int argc, char** argv)
{
    ndn::examples::AccessController ac;
    try {
        ac.run();
    }
    catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
    }
    return 0;
}