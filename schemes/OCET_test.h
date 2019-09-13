//
// Created by alan on 19-9-14.
//

#ifndef ABELIB_OCET_TEST_H
#define ABELIB_OCET_TEST_H

#include "OCET.h"
#include <time.h>

class OCET_test {
private:
    pairing_t pairing;
public:
    OCET_test();
    void setup_test(signed long int num);
    void keygen_test(signed long int num);
    void encrypt_test(signed long int num);
    void transform1_test(signed long int num);
    void transform2_test(signed long int num);
    void trapdoor_test(signed long int num);
    void test_test(signed long int num);
    void decrypt_test(signed long int num);
};


#endif //ABELIB_OCET_TEST_H
