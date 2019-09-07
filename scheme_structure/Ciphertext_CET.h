//
// Created by alan on 19-8-25.
//

#ifndef ABELIB_CIPHERTEXT_CET_H
#define ABELIB_CIPHERTEXT_CET_H

#include "Ciphertext.h"

class Ciphertext_CET : public Ciphertext{
public:
    unsigned char* Cstar;
    Ciphertext_CET();
    Ciphertext_CET(string policy);
    Ciphertext_CET(access_structure *A);
    Ciphertext_CET(element_t_matrix *M, map<signed long int, string> *rho);
};


#endif //ABELIB_CIPHERTEXT_CET_H
