//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_CLASSIC_ABE_H
#define ABELIB_CLASSIC_ABE_H

#include "../basis.h"
#include "../scheme_structure/scheme_structure.h"

class CLASSIC_ABE {
protected:
    pairing_t pairing;
public:
    pairing_t *getPairing();

    virtual vector<Key*>* setUp() = 0;

    virtual Key* keyGen(Key *public_key, Key *master_key, vector<string> *attributes) = 0;

    virtual Ciphertext* encrypt(element_s *m, string policy, Key *public_key) = 0;

    virtual element_s* decrypt(Ciphertext *ciphertext, Key *secret_key, vector<string> *attributes) = 0;
};


#endif //ABELIB_CLASSIC_ABE_H
