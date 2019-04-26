//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_NUM_VECTOR_H
#define ABELIB_NUM_VECTOR_H

#include "../basis.h"

class num_vector {
private:
    vector<signed long int> value;
public:
    num_vector(signed long int len);

    void printVector();

    signed long int length();

    signed long int getElement(signed long int i);
    void setElement(signed long int i, signed long int elem);

    void pushBack(signed long int elem);

    void resizeValue(signed long int i);
};


#endif //ABELIB_NUM_VECTOR_H
