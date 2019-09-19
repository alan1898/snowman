//
// Created by alan on 19-9-18.
//

#ifndef ABELIB_CIPHERTEXT_DET_H
#define ABELIB_CIPHERTEXT_DET_H

#include "Ciphertext_CET.h"

class Ciphertext_DET : public Ciphertext_CET {
private:
    vector<signed long int> *J;
public:
    Ciphertext_DET();
    Ciphertext_DET(vector<signed long int> *J);
    vector<signed long int>* getJ();
};


#endif //ABELIB_CIPHERTEXT_DET_H
