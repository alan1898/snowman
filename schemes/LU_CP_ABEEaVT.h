//
// Created by alan on 19-10-24.
//

#ifndef ABELIB_LU_CP_ABEEAVT_H
#define ABELIB_LU_CP_ABEEAVT_H

#include "../basis.h"
#include "../scheme_structure/Ciphertext_CET.h"
#include "../scheme_structure/SecretKey.h"
#include "../utils/utils.h"
#include "../extend_math_operation/extend_math_operation.h"
#include "../chameleon_hash/chamhash.h"

class LU_CP_ABEEaVT {
private:
    pairing_t pairing;

    element_t g1_sample, g2_sample, gt_sample, zr_sample;
    int g1_length, g2_length, gt_length, zr_length;
public:
    element_s* H1(element_s *e);
    unsigned char* H2(element_s *e);

    element_s* computeXdelte(Ciphertext_CET *ct, SecretKey *ky, string pre_s, string post_s);
    element_s* computeV(Ciphertext_CET *ct, Key *sp_ch, Key *pk_ch, element_s *r_ch, element_t_matrix *M, map<signed long int, string> *rho);

    LU_CP_ABEEaVT();

    vector<Key*>* setUp();
    SecretKey* keyGen(Key *public_key, Key *master_key, vector<string> *attributes);
    SecretKey* trapdoor(SecretKey *secret_key);
    Ciphertext_CET* encrypt(Key *public_key, access_structure *A, unsigned char *message, Key *sp_ch, Key *pk_ch);
    bool* test(Key *public_key, Ciphertext_CET *CTA, SecretKey *TdSA, Ciphertext_CET *CTB, SecretKey *TdSB, Key *sp_ch, Key *pk_ch);
    unsigned char* decrypt(Key *public_key, Ciphertext_CET *ciphertext_cet, SecretKey *secret_key, Key *sp_ch, Key *pk_ch);
};


#endif //ABELIB_LU_CP_ABEEAVT_H
