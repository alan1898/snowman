//
// Created by alan on 19-9-23.
//

#ifndef ABELIB_ODETC_TEST_H
#define ABELIB_ODETC_TEST_H

#include "ODETC.h"

class ODETC_test {
private:
    pairing_t pairing;
public:
    ODETC_test();
    void setup_test(signed long int num);
    void keygen_test(signed long int num);
    void encrypt_test(signed long int num);
    void trapdoor_test(signed long int num);
    void transform1_test(signed long int num);
    void transform2_test(signed long int num);
    void test_test(signed long int num);
    void decrypt_test(signed long int num);
};


#endif //ABELIB_ODETC_TEST_H
