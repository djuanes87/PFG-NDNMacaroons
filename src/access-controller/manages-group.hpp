#include "e_macaroon.pb.h"

#include <ndn-cxx/security/key-chain.hpp>

#include <NDNMacaroon/macaroon.hpp>
#include <NDNMacaroon/macaroon-utils.hpp>

class ManagesGroup {
    public:

        std::string name;
        std::string prefix;

        ManagesGroup();
        void
        setArgs(std::string name, std::string prefix, std::string macLocation, std::string gkdLocation, std::string hint_shared_key_gkd);

        macaroons::e_macaroon getMacaroon();

        void addThirdPartyCaveat();

        void
        addEndorsement(std::string type ,const std::string NAME, const std::string PREFIX, std::shared_ptr<ndn::IdentityCertificate> cert, int index);

        int
        verificateMacaroon(std::string serialized_macaroon, ndn::name::Component encrypted_dm, ndn::Name session_key_name);

        ndn::ConstBufferPtr
        extractKeyGroup(ndn::name::Component enc_dm, ndn::Name key_public_producer, ndn::Name session_key_consumer);

        bool checkScope(std::string scope);

    private:

        ndn::SecTpmFileEnc m_secTpmFile;
        std::shared_ptr<macaroons::NDNMacaroon> macaroon;
        macaroons::e_macaroon e_macaroon;
        std::string gkdLocation;
        std::string macLocation;
        std::map<std::string, std::string> idsToSecrets;
        std::string hint_shared_key_gkd;

        // Example caveats
        std::string first_party_caveat = "time < 2022-02-27 08:22:00";

        void
        createMacaroon();

        int
        verify(macaroons::NDNMacaroon *M);

};
