//
// Created by alan on 19-9-20.
//

#ifndef ABELIB_DET_TEST_H
#define ABELIB_DET_TEST_H

#include "DET.h"
#include <time.h>

class DET_test {
private:
    pairing_t pairing;
public:
    DET_test();
    void setup_test(signed long int N, signed long int count, signed long int L1, signed long int L2, signed long int L3);
    void keygen_test(signed long int N, signed long int X__size, signed long int Y__size, signed long int count, signed long int L1, signed long int L2, signed long int L3);
    void trapdoor_test(signed long int N, signed long int X__size, signed long int Y__size, signed long int count, signed long int L1, signed long int L2, signed long int L3);
    void encrypt_test(signed long int N, signed long int J_size, signed long int X_size, signed long int Y_size, signed long int count, signed long int L1, signed long int L2, signed long int L3);
    void decrypt_test(signed long int N, signed long int J_size, signed long int X_size, signed long int Y_size, signed long int count, signed long int L1, signed long int L2, signed long int L3);
    void test_test(signed long int N, signed long int J_size, signed long int X_size, signed long int Y_size, signed long int count, signed long int L1, signed long int L2, signed long int L3);
};


#endif //ABELIB_DET_TEST_H
