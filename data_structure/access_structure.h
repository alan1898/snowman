//
// Created by alan on 19-8-30.
//

#ifndef ABELIB_ACCESS_STRUCTURE_H
#define ABELIB_ACCESS_STRUCTURE_H

#include "element_t_vector.h"
#include "element_t_matrix.h"

class access_structure {
private:
    element_t_vector *ID;
    element_t_matrix *M;
    map<signed long int, string> *rho;
    string *name;
public:
    access_structure();
    access_structure(element_t_vector *ID, element_t_matrix *M, map<signed long int, string> *rho, string *name);

    element_t_vector* getID();
    element_t_matrix* getM();
    map<signed long int, string>* getRho();
    string* getName();

    void setMSimply(element_t_matrix *M);
    void setRhoSimply(map<signed long int, string> *rho);

    void setM(element_t_matrix *M);
    void setRho(map<signed long int, string> *rho);
};


#endif //ABELIB_ACCESS_STRUCTURE_H
