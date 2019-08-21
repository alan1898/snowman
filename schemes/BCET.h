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

class BCET {
private:
    pairing_t pairing;
public:
    vector<Key*>* setUp();
    Key* keyGen(Key *public_key, Key *master_key, vector<string> *attributes);
    Key* trapdoor(Key *secret_key, vector<string> *attributes);
};


#endif //ABELIB_BCET_H
