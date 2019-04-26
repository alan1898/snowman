//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_EXTEND_MATH_OPERATION_H
#define ABELIB_EXTEND_MATH_OPERATION_H

#include "../basis.h"
#include "../data_structure/data_structure.h"

class extend_math_operation {
public:
    element_t_vector* multiply(element_t_matrix *M, element_t_vector *y);
    signed long int gaussElimination(element_t_vector* x, element_t_matrix *A, element_t_vector *b);
};


#endif //ABELIB_EXTEND_MATH_OPERATION_H
