//
// Created by alan on 19-9-5.
//

#ifndef ABELIB_CIPHERTEXT_HCET_H
#define ABELIB_CIPHERTEXT_HCET_H

#include "Ciphertext_CET.h"

class Ciphertext_HCET : public Ciphertext_CET {
private:
    map<string, access_structure*> *AA;
public:
    Ciphertext_HCET();
    Ciphertext_HCET(map<string, access_structure*> *AA);
    map<string, access_structure*>* getAA();
};


#endif //ABELIB_CIPHERTEXT_HCET_H
