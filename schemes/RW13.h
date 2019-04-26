//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_RW13_H
#define ABELIB_RW13_H

#include "../basis.h"
#include "../scheme_structure/scheme_structure.h"
#include "../extend_math_operation/extend_math_operation.h"
#include "../curves/curve_param.h"
#include "../utils/utils.h"
#include "CLASSIC_ABE.h"

class RW13 : public CLASSIC_ABE{
public:
    RW13();

    vector<Key*>* setUp();

    Key* keyGen(Key *public_key, Key *master_key, vector<string> *attributes);

    Ciphertext* encrypt(element_s *m, string policy, Key *public_key);

    element_s* decrypt(Ciphertext *ciphertext, Key *secret_key, vector<string> *attributes);
};


#endif //ABELIB_RW13_H
