//
// Created by alan on 19-9-5.
//

#include "Ciphertext_HCET.h"

Ciphertext_HCET::Ciphertext_HCET() : Ciphertext_CET(){
    this->AA = new map<string, access_structure*>();
}

Ciphertext_HCET::Ciphertext_HCET(map<string, access_structure *> *AA) : Ciphertext_CET() {
    this->AA = new map<string, access_structure*>();

    map<string, access_structure *>::iterator iterator1;
    for (iterator1 = AA->begin(); iterator1 != AA->end(); ++iterator1) {
        access_structure *as = new access_structure(iterator1->second->getID(), iterator1->second->getM(), iterator1->second->getRho(), iterator1->second->getName());
        this->AA->insert(pair<string, access_structure *>(iterator1->first, as));
    }
}

map<string, access_structure*>* Ciphertext_HCET::getAA() {
    return AA;
}