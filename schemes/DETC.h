//
// Created by alan on 19-9-12.
//

#ifndef ABELIB_DETC_H
#define ABELIB_DETC_H

#include "../basis.h"
#include "../scheme_structure/scheme_structure.h"
#include "../extend_math_operation/extend_math_operation.h"
#include "../curves/curve_param.h"
#include "../utils/utils.h"
#include "../chameleon_hash/chamhash.h"

class DETC {
private:
    pairing_t pairing;

    element_t g1_sample, g2_sample, gt_sample, zr_sample;
    int g1_length, g2_length, gt_length, zr_length;
public:
    element_s* H1(element_s *e);
    unsigned char* H2(element_s *e);

    element_s* computeXsub(Ciphertext_CET *ciphertext, SecretKey *key_x, string post_s);

    DETC();

    vector<Key*>* setUp(vector<string> *attributes);
    Ciphertext_CET* encrypt(Key *public_key, access_structure *A, unsigned char *message);
    SecretKey* keyGen(Key *public_key, Key *master_key, vector<string> *attributes);
    SecretKey* trapdoor(Key *public_key, Key *master_key, vector<string> *attributes);
    bool* test(Key *public_key, Ciphertext_CET *CTA, SecretKey *TdSA, Ciphertext_CET *CTB, SecretKey *TdSB);
    unsigned char* decrypt(Ciphertext_CET *ciphertext_cet, SecretKey *secret_key);
};


#endif //ABELIB_DETC_H
