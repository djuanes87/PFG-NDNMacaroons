#pragma once

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
//#include <ndn-cxx/security/cryptopp.hpp>
#include <ndn-cxx/util/time.hpp>

#include <NDNMacaroon/macaroon.hpp>
#include <NDNMacaroon/macaroon-utils.hpp>

namespace groups {

//#include "endorse-certificate.hpp"
class ManagesGroup
{
    public:

        std::string name;
        std::string prefix;
        std::string m_serialized;

        ManagesGroup(std::string name, std::string prefix);

    private:

        ndn::SecTpmFileEnc m_secTpmFile;
        std::shared_ptr<macaroons::NDNMacaroon> M;
        std::map<std::string, std::string> idsToSecrets;

        // Example caveats
        std::string first_party_caveat_1 = "account = 3735928559";
        std::string first_party_caveat_2 = "time < 2016-02-27 08:22:00";
        std::string first_party_caveat_3 = "email = alice@example.org";
        std::string first_party_caveat_4 = "IP = 127.0.0.1";
        std::string first_party_caveat_5 = "browser = Chrome";
        std::string first_party_caveat_6 = "action = deposit";
        std::string first_party_caveat_7 = "action = withdraw";
        std::string first_party_caveat_8 = "OS = Windows XP";

        void
        createMacaroon(const std::string location, ndn::SecTpmFileEnc* m_secTpmFile);

        void
        createThirdPartyCaveat();


};
}
