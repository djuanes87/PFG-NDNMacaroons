#include <ndn-cxx/security/key-chain.hpp>

#include <NDNMacaroon/macaroon.hpp>
#include <NDNMacaroon/macaroon-utils.hpp>

class Group {
    public:

        std::string name;

        Group();

        void
        setName(std::string);

        std::string
        getDischargueMacaroon(std::string gkd_location, uint8_t *caveat_key, uint8_t *identifier, size_t identifier_size);

        void
        addMember(std::string member);

        bool
        isMember(std::string name);

    private:

        ndn::SecTpmFileEnc m_secTpmFile;
        std::string discharge;
        std::set<std::string> members;

        // Example caveats
        std::string first_party_caveat = "time < 2018-02-27 08:22:00";

        void
        createDischargeMacaroon(std::string gkd_location, uint8_t *caveat_key, uint8_t *identifier, size_t identifier_size);


};