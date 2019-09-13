//
// Created by alan on 19-9-14.
//

#ifndef ABELIB_DETC_TEST_H
#define ABELIB_DETC_TEST_H

#include "DETC.h"

class DETC_test {
private:
    pairing_t pairing;
public:
    DETC_test();
    void setup_test(signed long int num);
    void keygen_test(signed long int num);
    void encrypt_test(signed long int num);
    void trapdoor_test(signed long int num);
    void test_test(signed long int num);
    void decrypt_test(signed long int num);
};


#endif //ABELIB_DETC_TEST_H
