//
// Created by alan on 19-9-3.
//

#include "SecretKey.h"

SecretKey::SecretKey() : Key(Key::SECRET){
    attributes = new vector<string>();
    kgc_name = new string();
}

SecretKey::SecretKey(vector<string> *attributes) : Key(Key::SECRET){
    this->attributes = new vector<string>();
    this->kgc_name = new string();

    vector<string>::iterator iterator1;
    for (iterator1 = attributes->begin(); iterator1 != attributes->end(); ++iterator1) {
        this->attributes->push_back(*iterator1);
    }
}

SecretKey::SecretKey(vector<string> *attributes, string *kgc_name)  : Key(Key::SECRET){
    this->attributes = new vector<string>();
    this->kgc_name = new string();

    vector<string>::iterator iterator1;
    for (iterator1 = attributes->begin(); iterator1 != attributes->end(); ++iterator1) {
        this->attributes->push_back(*iterator1);
    }

    *(this->kgc_name) = *kgc_name;
}

vector<string>* SecretKey::getAttributes() {
    return attributes;
}

string* SecretKey::getKgcName() {
    return kgc_name;
}