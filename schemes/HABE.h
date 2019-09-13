//
// Created by alan on 19-9-12.
//

#ifndef ABELIB_HABE_H
#define ABELIB_HABE_H

#include "../basis.h"
#include "../scheme_structure/scheme_structure.h"
#include "../extend_math_operation/extend_math_operation.h"
#include "../curves/curve_param.h"
#include "../utils/utils.h"
#include "../chameleon_hash/chamhash.h"
#include "openssl/sha.h"

class HABE {
private:
    pairing_t pairing;
    signed long int q;

    element_t g1_sample, g2_sample, gt_sample, zr_sample;
    int g1_length, g2_length, gt_length, zr_length;
public:
    element_s* computeXdelte(Ciphertext_HCET *ciphertext, SecretKey *key_x, string pre_s, string post_s);

    HABE();

    vector<Key*>* setUp(signed long int q);
    Key* authKeyGen(Key *public_key, Key *master_key, element_t_vector *ID);
    Key* authDelegate(Key *public_key, Key *SKID, element_t_vector *ID);
    SecretKey* userKeyGen(Key *public_key, Key *SKID, element_t_vector *ID, string *kgc_name, vector<string> *attributes);
    Ciphertext_HCET* encrypt(Key *public_key, map<string, access_structure*> *AA, element_s *m);
    element_s* decrypt(Ciphertext_HCET *ciphertext_hcet, SecretKey *secret_key);
};


#endif //ABELIB_HABE_H