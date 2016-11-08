#include <group.hpp>

Group::Group(){
	discharge = "";
}


void
Group::setName(std::string name){
	this->name = name;
}

std::string
Group::getDischargueMacaroon(std::string gkd_location, uint8_t *caveat_key, uint8_t *identifier, size_t identifier_size){
	if(discharge == ""){
		createDischargeMacaroon(gkd_location, caveat_key, identifier, identifier_size);
	}
	return discharge;
}

void
Group::addMember(std::string member){
	members.insert(member);
}

bool
Group::isMember(std::string userName){
	if(members.find(userName) != members.end()){
		return true;
	}
	return false;
}

void
Group::createDischargeMacaroon(std::string gkd_location, uint8_t *caveat_key, uint8_t *identifier, size_t identifier_size){

    macaroons::NDNMacaroon D(gkd_location, caveat_key,
                                identifier, identifier_size);

    D.addFirstPartyCaveat(first_party_caveat_2);
    discharge =  D.serialize();
    std::cout << "CREATE DM: " << discharge << std::endl;
}
