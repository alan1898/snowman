//
// Created by alan on 19-4-26.
//

#include "abe_key.h"

abe_key::abe_key() {}
abe_key::abe_key(abe_key::key_type type) {
    this->type = type;
}

abe_key::key_type abe_key::getType() {
    return type;
}
void abe_key::setType(abe_key::key_type type) {
    this->type = type;
}

element_s* abe_key::getComponent(string s) {
    map<string, element_s*>::iterator it;
    it = components.find(s);

    if (it == components.end()) {
        return NULL;
    } else {
        return (*it).second;
    }
}
void abe_key::insertComponent(string s, element_s *component) {
    element_t *insert_component = new element_t[1];
    element_init_same_as(*insert_component, component);
    element_set(*insert_component, component);
    components.insert(pair<string, element_s*>(s, *insert_component));
}

map<string, element_s*>* abe_key::getComponents() {
    return &components;
}