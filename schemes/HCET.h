//
// Created by alan on 19-8-26.
//

#ifndef ABELIB_HCET_H
#define ABELIB_HCET_H

#include "../basis.h"
#include "../scheme_structure/scheme_structure.h"
#include "../extend_math_operation/extend_math_operation.h"
#include "../curves/curve_param.h"
#include "../utils/utils.h"
#include "../chameleon_hash/chamhash.h"

class HCET {
private:
    pairing_t pairing;
    signed long int q;

    element_t g1_sample, g2_sample, gt_sample, zr_sample;
    int g1_length, g2_length, gt_length, zr_length;
public:
    element_s* H1(element_s *e);
    unsigned char* H2(element_s *e);

    element_s* computeXdelte(Ciphertext_HCET *ciphertext, SecretKey *key_x, string pre_s, string post_s);
    element_s* computeVj(Ciphertext_HCET *ct, Key *sp_ch, Key *pk_ch, element_s *r_ch, access_structure *structure);

    HCET();

    vector<Key*>* setUp(signed long int q);
    Key* authKeyGen(Key *public_key, Key *master_key, element_t_vector *ID);
    Key* authDelegate(Key *public_key, Key *SKID, element_t_vector *ID);
    SecretKey* userKeyGen(Key *public_key, Key *SKID, element_t_vector *ID, string *kgc_name, vector<string> *attributes);
    SecretKey* trapdoor(SecretKey *secret_key);
    Ciphertext_HCET* encrypt(Key *public_key, map<string, access_structure*> *AA, unsigned char *message, Key *sp_ch, Key *pk_ch);
    bool* test(Key *public_key, Ciphertext_HCET *CTA, SecretKey *TdSA, Ciphertext_HCET *CTB, SecretKey *TdSB, Key *sp_ch, Key *pk_ch);
    unsigned char* decrypt(Ciphertext_HCET *ciphertext_hcet, SecretKey *secret_key);
};


#endif //ABELIB_HCET_H
