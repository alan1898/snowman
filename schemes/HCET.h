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
public:
    element_s* H1(element_s *e);
    unsigned char* H2(element_s *e);

    element_s* computeXdelte(Ciphertext_CET *ciphertext, Key *key_x, vector<string> *attributes, access_structure *structure, string kgc_name, string pre_s, string post_s);
    element_s* computeVj(Ciphertext_CET *ct, Key *sp_ch, Key *pk_ch, element_s *r_ch, access_structure *structure, string kgc_name);

    vector<Key*>* setUp(signed long int q);
    Key* authKeyGen(Key *public_key, Key *master_key, element_t_vector *ID);
    Key* authDelegate(Key *public_key, Key *SKID, element_t_vector *ID);
    Key* userKeyGen(Key *public_key, Key *SKID, element_t_vector *ID, vector<string> *attributes);
    Key* trapdoor(Key *secret_key, vector<string> *attributes);
    Ciphertext_CET* encrypt(Key *public_key, vector<access_structure*> *A, element_s *m, Key *sp_ch, Key *pk_ch);
};


#endif //ABELIB_HCET_H
