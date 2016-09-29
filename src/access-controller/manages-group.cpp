
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
//#include <ndn-cxx/security/cryptopp.hpp>
#include <ndn-cxx/util/time.hpp>

#include "manages-group.hpp"

//#include "logging.h"
namespace groups {
using std::vector;
using macaroons::NDNMacaroon;
using macaroons::NDNMacaroonVerifier;

ManagesGroup::ManagesGroup(std::string name, std::string prefix)
{
    this->name = name;
    this->prefix = prefix;
    createMacaroon(prefix, &m_secTpmFile);
}

void
ManagesGroup::createMacaroon(const std::string location, ndn::SecTpmFileEnc* m_secTpmFile)
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

    m_serialized = M->serialize();
}

void
ManagesGroup::createThirdPartyCaveat(){
    std::cout << "/* message */" << std::endl;
}
}
