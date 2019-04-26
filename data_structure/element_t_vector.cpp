//
// Created by alan on 19-4-26.
//

#include "element_t_vector.h"

/**
 * constructor
 */
element_t_vector::element_t_vector() {}
element_t_vector::element_t_vector(signed long int len, element_s *sample_element) {
    for (signed long int i = 0; i < len; ++i) {
        element_t *initialization_element = new element_t[1];
        element_init_same_as(*initialization_element, sample_element);
        value.push_back(*initialization_element);
    }
}
element_t_vector::element_t_vector(const element_t_vector &v) {
    value.resize(0);

    for (signed long int i = 0; i < v.length(); ++i) {
        pushBack(v.getElement(i));
    }
}

/**
 * assignment operator overload(deep copy)
 * @param v the right operand
 * @return *this
 */
element_t_vector& element_t_vector::operator=(const element_t_vector &v) {
    value.resize(0);

    for (signed long int i = 0; i < v.length(); ++i) {
        pushBack(v.getElement(i));
    }

    return *this;
}

/**
 * formatted output of the vector
 */
void element_t_vector::printVector() {
    signed long int len = length();

    for (signed long int i = 0; i < len; i++) {
        if (len - 1 == i) {
            element_printf("%B\n", value[i]);
        } else {
            element_printf("%B ", value[i]);
        }
    }
}

/**
 * get the length of the vector
 * @return the length of the vector
 */
signed long int element_t_vector::length() const {
    return value.size();
}

/**
 * get the element with the index 'i'
 * @param i the index
 * @return the element with the index
 */
element_s* element_t_vector::getElement(signed long int i) const {
    return value[i];
}
/**
 * set 'elem' to the element with the index 'i'
 * @param i the index
 * @param elem 'elem'
 */
void element_t_vector::setElement(signed long int i, element_s *elem) {
    element_set(value[i], elem);
}

/**
 * add 'elem' to the end of the vector
 * @param elem 'elem'
 */
void element_t_vector::pushBack(element_s *elem) {
    element_t *initialization_element = new element_t[1];
    element_init_same_as(*initialization_element, elem);
    value.push_back(*initialization_element);

    element_set(value[length() - 1], elem);
}

/**
 * resize the vector
 * @param i the new size
 */
void element_t_vector::resizeValue(signed long int i) {
    value.resize(i);
}