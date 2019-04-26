//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_ABE_KEY_H
#define ABELIB_ABE_KEY_H

#include "../basis.h"

class abe_key {
public:
    enum key_type { PUBLIC, MASTER, SECRET };
protected:
    key_type type;
    map<string, element_s*> components;
public:
    abe_key();
    abe_key(abe_key::key_type type);
    abe_key::key_type getType();
    void setType(abe_key::key_type type);

    element_s* getComponent(string s);
    void insertComponent(string s, element_s *component);

    map<string, element_s*>* getComponents();
};


#endif //ABELIB_ABE_KEY_H
