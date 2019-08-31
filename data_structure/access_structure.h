//
// Created by alan on 19-8-30.
//

#ifndef ABELIB_ACCESS_STRUCTURE_H
#define ABELIB_ACCESS_STRUCTURE_H

#include "element_t_vector.h"
#include "element_t_matrix.h"

class access_structure {
public:
    element_t_vector *ID;
    element_t_matrix *M;
    map<signed long int, string> *rho;
    string *name;
};


#endif //ABELIB_ACCESS_STRUCTURE_H
