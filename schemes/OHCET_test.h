//
// Created by alan on 19-9-14.
//

#ifndef ABELIB_OHCET_TEST_H
#define ABELIB_OHCET_TEST_H

#include "OHCET.h"
#include <time.h>

class OHCET_test {
private:
    pairing_t pairing;
public:
    OHCET_test();

    void setup_test(signed long int num);
    void authkeygen_test(signed long int num);
    void authdelegate_test(signed long int num);
    void userkeygen_test(signed long int size_ID, signed long int num_attr);
    void trapdoor_test(signed long int num_attr);
    void encrypt_test(signed long int num_kgc, signed long int size_ID, signed long int num_attr);
};


#endif //ABELIB_OHCET_TEST_H
