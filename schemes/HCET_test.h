//
// Created by alan on 19-9-14.
//

#ifndef ABELIB_HCET_TEST_H
#define ABELIB_HCET_TEST_H

#include "HCET.h"
#include <time.h>

class HCET_test {
private:
    pairing_t pairing;
public:
    HCET_test();

    void setup_test(signed long int num);
    void authkeygen_test(signed long int num);
    void authdelegate_test(signed long int num);
    void userkeygen_test(signed long int size_ID, signed long int num_attr);
    void trapdoor_test(signed long int num_attr);
    void encrypt_test(signed long int num_kgc, signed long int size_ID, signed long int num_attr);
//    void decrypt_test(signed long int size_ID, signed long int num_attr);
};


#endif //ABELIB_HCET_TEST_H
