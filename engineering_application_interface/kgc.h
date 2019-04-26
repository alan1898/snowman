//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_KGC_H
#define ABELIB_KGC_H

#include "../basis.h"
#include "../schemes/schemes.h"
#include "../message_serialization/message_serialization.h"

class kgc {
private:
    CLASSIC_ABE *classic_abe;
public:
    kgc(string scheme);

    string setUp();

    string keyGen(string public_key_json_str, string master_key_json_str, string attributes_json_str);
};


#endif //ABELIB_KGC_H
