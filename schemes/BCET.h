//
// Created by alan on 19-8-21.
//

#ifndef ABELIB_BCET_H
#define ABELIB_BCET_H


#include "../basis.h"
#include "../scheme_structure/scheme_structure.h"
#include "../extend_math_operation/extend_math_operation.h"
#include "../curves/curve_param.h"
#include "../utils/utils.h"
#include "../chameleon_hash/chamhash.h"

class BCET {
private:
    pairing_t pairing;

    element_t g1_sample, g2_sample, gt_sample, zr_sample;
    int g1_length, g2_length, gt_length, zr_length;
public:
    element_s* H1(element_s *e);
    unsigned char* H2(element_s *e);

    element_s* computeXdelte(Ciphertext_CET *ct, Key *ky, vector<string> *sa, string pre_s, string post_s);
    element_s* computeV(Ciphertext_CET *ct, Key *sp_ch, Key *pk_ch, element_s *r_ch, element_t_matrix *M, map<signed long int, string> *rho);

    BCET();

    vector<Key*>* setUp();
    Key* keyGen(Key *public_key, Key *master_key, vector<string> *attributes);
    Key* trapdoor(Key *secret_key, vector<string> *attributes);
    Ciphertext_CET* encrypt(Key *public_key, string policy, element_s *m, Key *sp_ch, Key *pk_ch);
    bool* test(Key *public_key, Ciphertext_CET *CTA, Key *TdSA, vector<string> *SA, Ciphertext_CET *CTB, Key *TdSB, vector<string> *SB, Key *sp_ch, Key *pk_ch);
    element_s* decrypt(Ciphertext_CET *ciphertext_cet, Key *secret_key, vector<string> *attributes);
};


#endif //ABELIB_BCET_H
