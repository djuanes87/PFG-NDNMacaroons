
#include <manages-group.hpp>

using std::vector;
using macaroons::NDNMacaroon;
using macaroons::NDNMacaroonVerifier;

ManagesGroup::ManagesGroup(){}

void
ManagesGroup::setArgs(std::string name, std::string prefix, std::string macLocation, std::string gkdLocation, std::string hint_shared_key_gkd)
{
    this->name = name;
    this->prefix = prefix;
    this->gkdLocation = gkdLocation;
    this->macLocation = macLocation;
    this->hint_shared_key_gkd = hint_shared_key_gkd;
    createMacaroon();
}


macaroons::e_macaroon
ManagesGroup::getMacaroon(){

    return e_macaroon;
}

void
ManagesGroup::createMacaroon()
{
    // 1. Create id, secret, and store id->secret in idsToSecrets

    // Create identifier as random number
    uint8_t id[MACAROON_SUGGESTED_SECRET_LENGTH];
    m_secTpmFile.generateRandomBlock(id, MACAROON_SUGGESTED_SECRET_LENGTH);
    // Create secret as random number
    uint8_t secret[MACAROON_SUGGESTED_SECRET_LENGTH];
    m_secTpmFile.generateRandomBlock(secret, MACAROON_SUGGESTED_SECRET_LENGTH);

    idsToSecrets[std::string(id, id + MACAROON_SUGGESTED_SECRET_LENGTH)] =
    std::string(secret, secret + MACAROON_SUGGESTED_SECRET_LENGTH);

    // 2. create macaroon
    macaroon = std::make_shared<macaroons::NDNMacaroon>(macLocation, secret, id, MACAROON_SUGGESTED_SECRET_LENGTH);

    // 3. add first party caveats
    macaroon->addFirstPartyCaveat (first_party_caveat);
}

void
ManagesGroup::addThirdPartyCaveat(){
    uint8_t caveat_key_buf[MACAROON_SUGGESTED_SECRET_LENGTH];
    m_secTpmFile.generateRandomBlock(caveat_key_buf, MACAROON_SUGGESTED_SECRET_LENGTH);
    macaroon->addThirdPartyCaveat( gkdLocation + "/getDischargeMacaroon/" + hint_shared_key_gkd,
	  			                  "group=="+name, caveat_key_buf,
                                  bind(macaroons::encryptIdentifier, _1, _2, _3, true, hint_shared_key_gkd, &m_secTpmFile));
    e_macaroon.set_macaroon (macaroon->serialize());

}

bool
ManagesGroup::checkScope(std::string scope){
    ndn::Name scope_name(scope);
    ndn::Name prefix_name(prefix);
    for(unsigned int i = 2; i < prefix_name.size(); i++){
        if(scope_name.at(i).toUri() != prefix_name.at(i).toUri()){
            return false;
        }
    }
    return true;
}
int
ManagesGroup::verificateMacaroon(std::string serialized_macaroon, ndn::name::Component encrypted_dm, ndn::Name session_key_name){

    std::cout << "Construyendo macaroon" << std::endl;

    macaroons::NDNMacaroon M = macaroons::NDNMacaroon(serialized_macaroon);
    std::cout << "Macaroon construido" << std::endl;

    std::cout << "*** num third party requests " << M.getNumThirdPartyCaveats() << std::endl;
    ndn::ConstBufferPtr decrypted_dm = m_secTpmFile.decryptInTpm(encrypted_dm.value(),
                                                                encrypted_dm.value_size(),
                                                                session_key_name,
                                                                /*symmetric*/ true);

    std::string dm_serialized = std::string(decrypted_dm->buf(), decrypted_dm->buf() + decrypted_dm->size());
    M.addDischarge(std::string(decrypted_dm->buf(), decrypted_dm->buf() + decrypted_dm->size()));
    std::cout << "*** added discharge, nms: " << M.getNumDischargeM() << std::endl;

    bool result = verify(&M);
    std::cout << "RESULT: "<< result << std::endl;
    if (!result) {
        std::cout << "verified!" << std::endl;
    } else {
        std::cout << "Not verified!" << std::endl;
    }
    return result;

}

ndn::ConstBufferPtr
ManagesGroup::extractKeyGroup(ndn::name::Component enc_dm, ndn::Name key_public_producer, ndn::Name session_key_consumer) {
    size_t sig_sz;
    const unsigned char* signature;
    const struct macaroon *dischargue;
    enum macaroon_returncode err;

    ndn::ConstBufferPtr decrypted_dm = m_secTpmFile.decryptInTpm(enc_dm.value(),
                                                                enc_dm.value_size(),
                                                                session_key_consumer,
                                                                /*symmetric*/ true);

    std::string dm = std::string(decrypted_dm->buf(), decrypted_dm->buf() + decrypted_dm->size());
    dischargue = macaroon_deserialize(dm.c_str(), &err);
    macaroon_signature(dischargue, &signature, &sig_sz);
    std::string key_group =  std::string(signature, signature + sig_sz);

    std::cout << "KEY GROUP:  "<< key_group << std::endl;

    return m_secTpmFile.encryptInTpm((uint8_t*) key_group.c_str(),
                            key_group.size(),
                            key_public_producer,
                            false);
}

void
ManagesGroup::addEndorsement(std::string type ,const std::string NAME, const std::string PREFIX, std::shared_ptr<ndn::IdentityCertificate> cert, int index){

    macaroons::e_macaroon::Endorsement* endorsement = e_macaroon.add_endorsements();

    std::cout<<">>>> GENERATE Endorsement >>>>>>>>>>>>>>>>>>>>>>>"<<std::endl;

    endorsement->set_kind (type);
    endorsement->set_name(PREFIX);
    std::cout << PREFIX << std::endl;

    endorsement->set_certname(cert->getName().getPrefix(-1).toUri());
    std::cout << cert->getName().getPrefix(-1).toUri() << std::endl;

    std::string certname = e_macaroon.endorsements(index).certname();
    std::cout << "certname:   " << std::endl;
    std::cout << certname << std::endl;
    ndn::Name keyName = ndn::IdentityCertificate::certificateNameToPublicKeyName(certname);
    std::cout << "keyname:   " << std::endl;
    std::cout << keyName.toUri() << std::endl;
    std::cout<<">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"<<std::endl;

}

int
ManagesGroup::verify(macaroons::NDNMacaroon *M){
    macaroons::NDNMacaroonVerifier verifier;

    ndn::time::system_clock::TimePoint now = ndn::time::system_clock::now();
    uint64_t time = (uint64_t)ndn::time::toUnixTimestamp(now).count();
    verifier.satisfyGeneral(macaroons::check_time, (void*)(&time));

    std::cout << "SECRET:   " << idsToSecrets[M->getIdentifier()] <<std::endl;
    std::string errorCode;
    int result = M->verify(&verifier, (uint8_t *)idsToSecrets[M->getIdentifier()].c_str(), errorCode);

    std::cout << "Verifying ..." << std::endl;
    return result;
}

