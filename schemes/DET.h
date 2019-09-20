//
// Created by alan on 19-9-18.
//

#ifndef ABELIB_DET_H
#define ABELIB_DET_H

#include "../basis.h"
#include "../scheme_structure/scheme_structure.h"
#include "../extend_math_operation/extend_math_operation.h"
#include "../curves/curve_param.h"
#include "../utils/utils.h"
#include "../chameleon_hash/chamhash.h"

#define WILDCARD 0
#define POSITIVE 1
#define NEGATIVE 2

class DET {
private:
    pairing_t pairing;

    element_t g1_sample, g2_sample, gt_sample, zr_sample;
    int g1_length, g2_length, gt_length, zr_length;

    signed long int N;

    signed long int L1, L2, L3;
public:
    vector<signed long int>* testJ();
    vector<signed long int>* testX();
    vector<signed long int>* testY();
    vector<signed long int>* computeA(vector<signed long int> *J);
    element_s* computeT(vector<signed long int> *a);
    element_s* computeIWK(signed long int i, vector<signed long int> *J);
    unsigned char* H1(element_s *e);
    element_s* H2(element_s *e);
    element_s* computeV(Ciphertext_DET *CT, Key *SK, string C2_str, string sk_str, string pre_str, string post_str);

    DET();
    DET(signed long int L1, signed long int L2, signed long int L3);

    vector<Key*>* setUp(signed long int N);
    Ciphertext_DET* encrypt(Key *public_key, vector<signed long int> *J, vector<signed long int> *X, vector<signed long int> *Y, unsigned char *message);
    Key* keyGen(Key *public_key, Key *master_key, vector<signed long int> *X_, vector<signed long int> *Y_);
    Key* trapdoor(Key *secret_key, vector<signed long int> *X_, vector<signed long int> *Y_);
};


#endif //ABELIB_DET_H
