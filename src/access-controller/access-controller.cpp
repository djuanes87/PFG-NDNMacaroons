#include "e_macaroon.pb.h"

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
//#include <ndn-cxx/security/cryptopp.hpp>
#include <ndn-cxx/security/validator-config.hpp>
#include <ndn-cxx/util/time.hpp>



#include <NDNMacaroon/macaroon.hpp>
#include <NDNMacaroon/macaroon-utils.hpp>
//#include <manages-group.hpp>

#include <boost/regex.hpp>

#include <map>


const std::string KEYNAMES_FILENAME="./keys.txt";
const std::string VALIDATOR_FILENAME="./config/validation-producer.conf";

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
// Additional nested namespace could be used to prevent/limit name contentions
namespace ndn {
    namespace examples {
        class AccessController : noncopyable
        {
            public:
                AccessController() {
                    loadKeyNames();
                    hint_shared_key_third_party = "code1234";
                    //Pido las claves publicas de Producer para poder fimar interest
                    //y poder cifrar los paquetes de datos.
                    AccessController::fetchCertificate(m_princKeyNames[PRODUCER_KSK]);
                    AccessController::fetchCertificate(m_princKeyNames[PRODUCER_DSK]);
                    //Crea el macaroon
                    AccessController::getMacaroon();
                }

                void
                run(){
                    // -- ++ --access controler requests the public keys producer -- ++ --

                    // Waits interest identity, to provide key
                    m_face.setInterestFilter(m_accessControllerIdentity,
                                          bind(&AccessController::onKeyInterest, this, _1, _2),
                                          RegisterPrefixSuccessCallback(),
                                          bind(&AccessController::onRegisterFailed, this, _1, _2));

                    m_face.processEvents();
                }

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
                        std::cout <<  " PRODUCER_DSK = " << m_princKeyNames[PRODUCER_DSK] << std::endl;

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
                            m_accessControllerIdentity = matches[1];
                        }
                        std::cout << " Access Controller identity = " << m_accessControllerIdentity << std::endl;
                    }
                }


            private:

/* ******************* PIDE LAS CLAVES PUBLICAS ******************************* */
                void
                onEndorseCertificateInternal(const Interest& interest, Data& data)
                {
                    std::cout << "Recibido Data " << std::endl;
                }

                void
                onEndorseCertificateInternalTimeout(const Interest& interest)
                {
                    std::cout << "Can't fetch certificate" <<  interest << std::endl;
                }

                void
                fetchCertificate(std::string certname){


                    shared_ptr<IdentityCertificate> cert =
                        m_keyChain.getCertificate(m_keyChain.getDefaultCertificateNameForKey(ndn::Name(certname)));
                    Name interestName(cert->getName().getPrefix(-1).toUri());

                    Interest interest(interestName);
                    interest.setInterestLifetime(time::milliseconds(2000));
                    interest.setMustBeFresh(true);
                    m_face.expressInterest(interest,
                                        bind(&AccessController::onEndorseCertificateInternal,
					                    this, _1, _2),
				                        bind(&AccessController::onEndorseCertificateInternalTimeout,
                                        this, _1));
                    std::cout << "--- Interest Certificate ---" << interest << std::endl;
                }
/*******************************************************************************/

/************************** DEVUELVE LAS CLAVES A QUIEN SE LAS PIDE ************/
                void
                onKeyInterest(const InterestFilter& filter, const Interest& interest)
                {


                    Name keyName = ndn::Name(m_accessControllerIdentity + "/" + interest.getName().at(4).toUri());
                    std::cout << keyName << std::endl;
                    std::cout << "<< I Certificate: " << interest << std::endl;

                    try {
                        // Create Data packet
                        shared_ptr<IdentityCertificate> cert =
                        m_keyChain.getCertificate(m_keyChain.getDefaultCertificateNameForKey(keyName));

                        std::cout << "<< Certificate: " << *cert << std::endl;
                        m_face.put(*cert);
                        std::cout << "---- SEND ----" << std::endl;
                    }
                    catch (const std::exception& ) {
                        std::cout << "The certificate: " << interest.getName()
                        << " does not exist"  << std::endl;
                    }
                }

                void
                onRegisterFailed(const Name& prefix, const std::string& reason)
                {
                    std::cerr << "ERROR: Failed to register prefix \""
                    << prefix << "\" in local hub's daemon (" << reason << ")"
                    << std::endl;
                    m_face.shutdown();
                }

/*******************************************************************************/
/*************************** CREA LAS MACAROON DE GRUPO ************************/
                void
                getMacaroon() {
                    ndn::SecTpmFileEnc m_secTpmFile;
                    const std::string PRODUCER_KSK_NAME = m_princKeyNames[ACCESS_CONTROLLER_KSK];

                    std::cout << " Generating macaroon: " << std::endl;

                    // get session key and store in secTpmFile with session_key_name
                    //ndn::Name session_key_name("/session-key-producer-consumer1");
                    //getSessionKeyFromInterest(interest, SESSION_KEY_POS, session_key_name);

                    // Create macaroon
                    create_macaroon(ACCESS_CONTROLLER_PREFIX, &m_secTpmFile);
                    std::cout << ">>>" << std::endl;

                    // Encrypt serialized macaroon with session_key
                    std::string serialized_macaroon = M->serialize();
                    std::cout << serialized_macaroon << std::endl;

                    createThirdPartyCaveat("Doctors");

                }

                void
                create_macaroon(const std::string location, ndn::SecTpmFileEnc* m_secTpmFile)
                {
                    // 1. Create id, secret, and store id->secret in idsToSecrets

                    // Create identifier as random number
                    uint8_t id[MACAROON_SUGGESTED_SECRET_LENGTH];
                    m_secTpmFile->generateRandomBlock(id, MACAROON_SUGGESTED_SECRET_LENGTH);
                    // Create secret as random number
                    uint8_t secret[MACAROON_SUGGESTED_SECRET_LENGTH];
                    m_secTpmFile->generateRandomBlock(secret, MACAROON_SUGGESTED_SECRET_LENGTH);

                    idsToSecrets[std::string(id, id + MACAROON_SUGGESTED_SECRET_LENGTH)] =
                    std::string(secret, secret + MACAROON_SUGGESTED_SECRET_LENGTH);

                    // 2. create macaroon
                    M = std::make_shared<macaroons::NDNMacaroon>(location, secret, id,
                                                     MACAROON_SUGGESTED_SECRET_LENGTH);

                    // 3. add first party caveats
                    M->addFirstPartyCaveat (first_party_caveat_1);
                    M->addFirstPartyCaveat (first_party_caveat_2);
                    M->addFirstPartyCaveat (first_party_caveat_6);

                }// create_macaroon


/*******************************************************************************/
/******************** AÑADE AL MACARRON EL THIRD PARTY CAVEAT ******************/
                void
                createThirdPartyCaveat(std::string group) {

                    ndn::SecTpmFileEnc m_secTpmFile;
                    uint8_t caveat_key_buf[MACAROON_SUGGESTED_SECRET_LENGTH];
                    m_secTpmFile.generateRandomBlock(caveat_key_buf, MACAROON_SUGGESTED_SECRET_LENGTH);
                                                    M->addThirdPartyCaveat(DISCHARGE_MACAROON_PREFIX + hint_shared_key_third_party,
	  			                                    GROUP_NAME+group,
	  			                                    caveat_key_buf,
                                                    bind(macaroons::encryptIdentifier, _1, _2, _3, true, hint_shared_key_third_party, &m_secTpmFile));
                    //
                    // Create protobuf e_macaroon message: macaroon, [endorsement]
                    //
                    // 1. macaroon newM->serialize()
                    e_macaroon.set_macaroon (M->serialize());

                    addEndorsement("ksk", m_princKeyNames[ACCESS_CONTROLLER_KSK], ACCESS_CONTROLLER_PREFIX);
                    addEndorsement("dsk", m_princKeyNames[ACCESS_CONTROLLER_DSK], ACCESS_CONTROLLER_PREFIX);
                    addEndorsement("ksk", m_princKeyNames[GROUP_KEYS_DISTRIBUTOR_KSK], DISCHARGE_MACAROON_PREFIX);
                    addEndorsement("dsk", m_princKeyNames[GROUP_KEYS_DISTRIBUTOR_DSK], DISCHARGE_MACAROON_PREFIX);

                    std::cout << "Macaroon:   " << std::endl;

                }

                void
                addEndorsement(std::string type ,const std::string NAME, const std::string PREFIX){

                    // 2. ksk producer endorsement == (type, name, certname, hash)
	                macaroons::e_macaroon::Endorsement* endorsement = e_macaroon.add_endorsements();

                    std::cout<<">>>>"<<std::endl;

	                shared_ptr<IdentityCertificate> cert =
	                m_keyChain.getCertificate(m_keyChain.getDefaultCertificateNameForKey(ndn::Name(NAME)));
	                std::cout<<">>>>"<<std::endl;
	                std::stringstream ss;
	                {
                        using namespace CryptoPP;
	                    SHA256 hash;
                        StringSource(cert->wireEncode().wire(), cert->wireEncode().size(), true,
                        new HashFilter(hash, new FileSink(ss)));
	                }
                    endorsement->set_kind (type);
                    endorsement->set_name(PREFIX);
                    // set certname, which doesn't include the version, i.e.,
                    // the last component of the name
                    endorsement->set_certname(cert->getName().getPrefix(-1).toUri());
                    endorsement->set_hash(ss.str());
                }





/*******************************************************************************/

                const std::string ACCESS_CONTROLLER_PREFIX = "/example/accesscontroller";
                const std::string DISCHARGE_MACAROON_PREFIX = "/example/groupKeysDistributor/getDischargeMacaroon/";
                const std::string GROUP_NAME = "group==";
                enum {
                    // 0  --> /example
                    // 1  --> /producer
                    COMMAND_POS         = 2, // Position of command in name: getMacaroon, deposit, withdraw
                    SESSION_KEY_POS     = 3, // Position session Key
                    MACAROON_POS        = 4, // Position of macaroon in name.

                    // Discharge i is in MACAROON_POS + i ...
                    INTEREST_SIG_VALUE  = -1,
                    INTEREST_SIG_INFO   = -2
                };
                enum princEnum_t {PRODUCER_KSK, PRODUCER_DSK, GROUP_KEYS_DISTRIBUTOR_KSK, GROUP_KEYS_DISTRIBUTOR_DSK,
                     ACCESS_CONTROLLER_KSK, ACCESS_CONTROLLER_DSK};

                //Macaroon
                std::shared_ptr<macaroons::NDNMacaroon> M;
                macaroons::e_macaroon e_macaroon;
                std::string hint_shared_key_third_party;

                // m_accessControllerIdentity is extracted from KEYNAMES_FILENAME
                std::string m_accessControllerIdentity;
                // m_princKeyNames: principal keynames are extracted from KEYNAMES_FILENAME
                std::map<princEnum_t, std::string> m_princKeyNames;

                // Macaroon is created from secret: Map <macaroonId, secret>
                std::map<std::string, std::string> idsToSecrets;

                Face m_face;
                KeyChain m_keyChain;
                ValidatorConfig m_validator;

                // Example caveats
                std::string first_party_caveat_1 = "account = 3735928559";
                std::string first_party_caveat_2 = "time < 2016-02-27 08:22:00";
                std::string first_party_caveat_3 = "email = alice@example.org";
                std::string first_party_caveat_4 = "IP = 127.0.0.1";
                std::string first_party_caveat_5 = "browser = Chrome";
                std::string first_party_caveat_6 = "action = deposit";
                std::string first_party_caveat_7 = "action = withdraw";
                std::string first_party_caveat_8 = "OS = Windows XP";
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
