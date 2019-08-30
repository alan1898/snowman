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

    vector<Key*>* setUp(signed long int q);
    Key* authKeyGen(Key *public_key, Key *master_key, element_t_vector *ID);
    Key* authDelegate(Key *public_key, Key *SKID, element_t_vector *ID);
    Key* userKeyGen(Key *public_key, Key *SKID, vector<string> *attributes);
    Key* trapdoor(Key *secret_key, vector<string> *attributes);
};


#endif //ABELIB_HCET_H
