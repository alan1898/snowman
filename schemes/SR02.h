//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_SR02_H
#define ABELIB_SR02_H

#include "../basis.h"
#include "../data_structure/data_structure.h"
#include "../extend_math_operation/extend_math_operation.h"
#include "../curves/curve_param.h"
#include "../scheme_structure/scheme_structure.h"
#include "../utils/utils.h"

class SR02 {
private:
    pairing_t pairing;

    void element_F(element_t f_t, element_t u, element_t h, element_t t);
public:
    vector<abe_key*>* setUp();

    vector<abe_key*>* userKG(abe_key *public_key, string user_id);

    void pubKG(abe_key *public_key, abe_key *master_key, string user_id, abe_key *pk, vector<string> *attributes, sar_kgc *kgc);

    void tKeyUp(abe_key *public_key, abe_key *master_key, sar_kgc *kgc);

    abe_key* tranKG(abe_key *public_key, string user_id, vector<string> *attributes, sar_kgc *kgc);

    abe_ciphertext* encrypt(abe_key *public_key, string policy, element_s *t, element_s *m);

    abe_key* transform(abe_key *public_key, string user_id, vector<string> *attributes, abe_ciphertext *CT, abe_key *tkid, element_s *t);

    element_s* decrypt(string user_id, abe_key *sk, abe_key *CT_);
};


#endif //ABELIB_SR02_H
