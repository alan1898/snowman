//
// Created by alan on 19-9-18.
//

#include "Ciphertext_DET.h"

Ciphertext_DET::Ciphertext_DET() : Ciphertext_CET() {
    J = new vector<signed long int>();
}

Ciphertext_DET::Ciphertext_DET(vector<signed long int> *J) : Ciphertext_CET() {
    this->J = new vector<signed long int>();

    for (signed long int i = 0; i < J->size(); ++i) {
        this->J->push_back(J->at(i));
    }
}

vector<signed long int>* Ciphertext_DET::getJ() {
    return J;
}