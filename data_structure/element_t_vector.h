//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_ELEMENT_T_VECTOR_H
#define ABELIB_ELEMENT_T_VECTOR_H

#include "../basis.h"

class element_t_vector {
private:
    vector<element_s*> value;
public:
    element_t_vector();
    element_t_vector(signed long int len, element_s *sample_element);
    element_t_vector(const element_t_vector& v);

    element_t_vector& operator=(const element_t_vector& v);

    void printVector();

    signed long int length() const;

    element_s* getElement(signed long int i) const;
    void setElement(signed long int i, element_s *elem);

    void pushBack(element_s *elem);

    void resizeValue(signed long int i);
};


#endif //ABELIB_ELEMENT_T_VECTOR_H
