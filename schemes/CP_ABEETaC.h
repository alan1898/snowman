//
// Created by alan on 19-10-24.
//

#ifndef ABELIB_CP_ABEETAC_H
#define ABELIB_CP_ABEETAC_H

#include "../basis.h"
#include "../scheme_structure/Ciphertext_CET.h"
#include "../scheme_structure/SecretKey.h"
#include "../utils/utils.h"
#include "../extend_math_operation/extend_math_operation.h"
#include "../curves/curve_param.h"

class CP_ABEETaC {
private:
    pairing_t pairing;

    element_t g1_sample, g2_sample, gt_sample, zr_sample;
    int g1_length, g2_length, gt_length, zr_length;
public:
    element_s* H1(element_s *e);
    unsigned char* H2(unsigned char* str, signed long int len);

    element_s* computeXsub(Ciphertext_CET *ciphertext, SecretKey *key_x, string post_s);
    unsigned char* computeH2Input(element_s * e_gg_alpha__s, Ciphertext_CET *ciphertext);

    CP_ABEETaC();

    vector<Key*>* setUp(vector<string> *attributes);
    Ciphertext_CET* encrypt(Key *public_key, access_structure *A, unsigned char *message);
    SecretKey* keyGen(Key *public_key, Key *master_key, vector<string> *attributes);
    SecretKey* trapdoor(Key *public_key, Key *master_key, vector<string> *attributes);
    bool* test(Key *public_key, Ciphertext_CET *CTA, SecretKey *TdSA, Ciphertext_CET *CTB, SecretKey *TdSB);
    unsigned char* decrypt(Key *public_key, Ciphertext_CET *ciphertext_cet, SecretKey *secret_key);
};


#endif //ABELIB_CP_ABEETAC_H
