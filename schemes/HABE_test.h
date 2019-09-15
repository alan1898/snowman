//
// Created by alan on 19-9-14.
//

#ifndef ABELIB_HABE_TEST_H
#define ABELIB_HABE_TEST_H

#include "HABE.h"
#include <time.h>

class HABE_test {
private:
    pairing_t pairing;
public:
    HABE_test();

    void setup_test(signed long int num);
    void authkeygen_test(signed long int num);
    void authdelegate_test(signed long int num);
    void userkeygen_test(signed long int size_ID, signed long int num_attr);
    void encrypt_test(signed long int max_kgc, signed long int num_kgc, signed long int size_ID, signed long int num_attr);
    void decrypt_test(signed long int size_ID, signed long int num_attr);
};


#endif //ABELIB_HABE_TEST_H
