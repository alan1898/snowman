//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_BSW07_H
#define ABELIB_BSW07_H

#include "../basis.h"
#include "../data_structure/data_structure.h"
#include "../scheme_structure/scheme_structure.h"
#include "../curves/curve_param.h"
#include "CLASSIC_ABE.h"

class BSW07 : public CLASSIC_ABE {
private:
    element_s* decryptNode(Ciphertext *ciphertext, Key *secret_key, multiway_tree_node *x);
public:
    BSW07();

    vector<Key*>* setUp();

    Key* keyGen(Key *public_key, Key *master_key, vector<string> *attributes);

    Key* delegate(Key *public_key, Key *secret_key, vector<string> *attributes_);

    Ciphertext* encrypt(element_s *m, string policy, Key *public_key);

    element_s* decrypt(Ciphertext *ciphertext, Key *secret_key, vector<string> *attributes);
};


#endif //ABELIB_BSW07_H
