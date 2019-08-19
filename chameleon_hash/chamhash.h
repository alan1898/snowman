//
// Created by alan on 19-8-19.
//

#ifndef ABELIB_CHAMHASH_H
#define ABELIB_CHAMHASH_H


#include "../basis.h"
#include "../curves/curve_param.h"
#include "../scheme_structure/scheme_structure.h"

class chamhash {
private:
    pairing_t pairing;
public:
    chamhash();
    Key* setup();
    vector<Key*>* keygen(Key *sp);
    element_s* hash(Key *sp, Key *pk, element_s *m, element_s *r);
    element_s* forge(Key *sp, Key *pk, Key *sk, element_s *m, element_s *r, element_s *m_);
};


#endif //ABELIB_CHAMHASH_H
