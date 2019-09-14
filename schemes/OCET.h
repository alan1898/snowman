//
// Created by alan on 19-9-9.
//

#ifndef ABELIB_OCET_H
#define ABELIB_OCET_H

#include "../basis.h"
#include "../scheme_structure/scheme_structure.h"
#include "../extend_math_operation/extend_math_operation.h"
#include "../curves/curve_param.h"
#include "../utils/utils.h"
#include "../chameleon_hash/chamhash.h"

class OCET {
private:
    pairing_t pairing;

    element_t g1_sample, g2_sample, gt_sample, zr_sample;
    int g1_length, g2_length, gt_length, zr_length;
public:
    element_s* H1(element_s *e);
    unsigned char* H2(element_s *e);

    element_s* computeXdelte(Ciphertext_CET *ct, SecretKey *ky, string pre_s, string post_s);
    element_s* computeV(Ciphertext_CET *ct, Key *sp_ch, Key *pk_ch, element_s *r_ch, element_t_matrix *M, map<signed long int, string> *rho);

    OCET();

    vector<Key*>* setUp();
    vector<SecretKey*>* keyGen(Key *public_key, Key *master_key, vector<string> *attributes);
    vector<SecretKey*>* trapdoor(vector<SecretKey*> *secret_key);
    Ciphertext_CET* encrypt(Key *public_key, access_structure *A, unsigned char *message, Key *sp_ch, Key *pk_ch);
    Ciphertext_CET* transform(Key *public_key, SecretKey *key_x, string *key_type, Ciphertext_CET *ciphertext, Key *sp_ch, Key *pk_ch);
    bool* test(Key *public_key, Ciphertext_CET *ITA, vector<SecretKey*> *TdSA, Ciphertext_CET *ITB, vector<SecretKey*> *TdSB);
    unsigned char* decrypt(Key *public_key, Ciphertext_CET *IT, SecretKey *DK);
};


#endif //ABELIB_OCET_H
