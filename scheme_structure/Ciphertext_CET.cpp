//
// Created by alan on 19-8-25.
//

#include "Ciphertext_CET.h"

Ciphertext_CET::Ciphertext_CET() : Ciphertext() {}

Ciphertext_CET::Ciphertext_CET(string policy) : Ciphertext(policy){}

Ciphertext_CET::Ciphertext_CET(access_structure *A) : Ciphertext(A){}

Ciphertext_CET::Ciphertext_CET(element_t_matrix *M, map<signed long int, string> *rho) : Ciphertext(M, rho){}