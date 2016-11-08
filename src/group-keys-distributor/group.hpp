
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
        std::string first_party_caveat_1 = "account = 3735928559";
        std::string first_party_caveat_2 = "time < 2018-02-27 08:22:00";
        std::string first_party_caveat_3 = "email = alice@example.org";
        std::string first_party_caveat_4 = "IP = 127.0.0.1";
        std::string first_party_caveat_5 = "browser = Chrome";
        std::string first_party_caveat_6 = "action = deposit";
        std::string first_party_caveat_7 = "action = withdraw";
        std::string first_party_caveat_8 = "OS = Windows XP";

        void
        createDischargeMacaroon(std::string gkd_location, uint8_t *caveat_key, uint8_t *identifier, size_t identifier_size);


};