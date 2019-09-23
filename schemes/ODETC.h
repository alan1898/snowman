//
// Created by alan on 19-9-22.
//

#ifndef ABELIB_ODETC_H
#define ABELIB_ODETC_H

#include "../basis.h"
#include "../scheme_structure/scheme_structure.h"
#include "../extend_math_operation/extend_math_operation.h"
#include "../curves/curve_param.h"
#include "../utils/utils.h"
#include "../chameleon_hash/chamhash.h"

class ODETC {
private:
    pairing_t pairing;

    element_t g1_sample, g2_sample, gt_sample, zr_sample;
    int g1_length, g2_length, gt_length, zr_length;
public:
    element_s* H1(element_s *e);
    unsigned char* H2(unsigned char* str, signed long int len);

    element_s* computeXsub(Ciphertext_CET *ciphertext, SecretKey *key_x, string post_s);
    unsigned char* computeH2Input(element_s * e_gg_alpha__s, Ciphertext_CET *ciphertext);

    ODETC();

    vector<Key*>* setUp(vector<string> *attributes);
    Ciphertext_CET* encrypt(Key *public_key, access_structure *A, unsigned char *message);
    SecretKey* keyGen(Key *public_key, Key *master_key, vector<string> *attributes);
    SecretKey* trapdoor(Key *public_key, Key *master_key, vector<string> *attributes);
    Ciphertext_CET* transform(Ciphertext_CET *Ct, SecretKey *TkS, string *key_type);
    bool* test(Ciphertext_CET *ITA, SecretKey *TdSA, Ciphertext_CET *ITB, SecretKey *TdSB);
    unsigned char* decrypt(Key *public_key, Ciphertext_CET *IT, SecretKey *secret_key);
};


#endif //ABELIB_ODETC_H
