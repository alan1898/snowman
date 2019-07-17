//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_ELEMENT_T_MATRIX_H
#define ABELIB_ELEMENT_T_MATRIX_H

#include "../basis.h"
#include "element_t_vector.h"

class element_t_matrix {
private:
    vector<vector<element_s*> > value;
public:
    element_t_matrix();
    element_t_matrix(signed long int r, signed long int c, element_s *sample_element);

    void printMatrix();

    signed long int row();
    signed long int col();

    element_s* getElement(signed long int r, signed long int c);
    void setElement(signed long int r, signed long int c, element_s *elem);

    void pushBack(element_t_vector *v);
    void pushBack(element_t_vector *v, signed long int r);
};


#endif //ABELIB_ELEMENT_T_MATRIX_H
