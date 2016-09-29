//#include <validator-panel.hpp>

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
//#include <ndn-cxx/security/cryptopp.hpp>
#include <ndn-cxx/security/validator-config.hpp>
#include <ndn-cxx/util/time.hpp>

#include <NDNMacaroon/macaroon.hpp>
#include <NDNMacaroon/macaroon-utils.hpp>

#include <boost/regex.hpp>

#include <map>


const std::string KEYNAMES_FILENAME="./keys.txt";
const std::string VALIDATOR_FILENAME="./config/validation-producer.conf";

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
// Additional nested namespace could be used to prevent/limit name contentions
namespace ndn {
    namespace examples {
        class Producer : noncopyable
        {
            public:
                Producer() {
                    loadKeyNames();
                }

                void
                run(){
                    // -- ++ -- Direccion donde pedir datos -- ++ --

                    // Waits interest producer identity, to provide producer key
                    m_face.setInterestFilter(m_producerIdentity,
	 			                          bind(&Producer::onKeyInterest, this, _1, _2),
	 			                          RegisterPrefixSuccessCallback(),
	 			                          bind(&Producer::onRegisterFailed, this, _1, _2));

                    m_face.processEvents();
                }

                void
                loadKeyNames()
                {
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

                        boost::regex identity("(.*)/dsk-(.*)");
                        boost::cmatch matches;

                        if (boost::regex_match(line.c_str(), matches, identity)) {
                            m_producerIdentity = matches[1];
                        }
                        std::cout << "producer identity = " << m_producerIdentity << std::endl;
                    }
                }
/********************** DESVUELVE SUS CLAVES PUBLICAS ****************************/
                void
                onKeyInterest(const InterestFilter& filter, const Interest& interest)
                {


                    Name keyName = ndn::Name(m_producerIdentity + "/" + interest.getName().at(4).toUri());
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


            private:
                const std::string PRODUCER_PREFIX = "/example/producer";
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
                enum princEnum_t {PRODUCER_KSK, PRODUCER_DSK};

                // m_producerIdentity is extracted from KEYNAMES_FILENAME
                std::string m_producerIdentity;
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
  ndn::examples::Producer producer;
  try {
    producer.run();
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
  }
  return 0;
}
