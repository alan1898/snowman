//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_KEY_H
#define ABELIB_KEY_H

#include "../basis.h"

class Key {
public:
    enum key_type { PUBLIC, MASTER, SECRET };
protected:
    key_type type;
    map<string, element_s*> *g1_components;
    map<string, element_s*> *g2_components;
    map<string, element_s*> *gt_components;
    map<string, element_s*> *zr_components;

public:
    Key();
    Key(Key::key_type type);

    Key::key_type getType();
    void setType(Key::key_type type);

    element_s* getComponent(string s, string group);
    void insertComponent(string s, string group, element_s *component);

    map<string, element_s*>* getComponents(string group);

    element_s* getComponent(string s);

    void printKey();
};


#endif //ABELIB_KEY_H
