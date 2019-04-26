//
// Created by alan on 19-4-26.
//

#include "element_t_matrix.h"

/**
 * constructor
 */
element_t_matrix::element_t_matrix() {
    value.resize(0);
}
element_t_matrix::element_t_matrix(signed long int r, signed long int c, element_s *sample_element) {
    value.resize(r);

    for (signed long int i = 0; i < r; ++i) {
        for (signed long int j = 0; j < c; ++j) {
            element_t *initialization_element = new element_t[1];
            element_init_same_as(*initialization_element, sample_element);
            value[i].push_back(*initialization_element);
        }
    }
}

/**
 * formatted output of the matrix
 */
void element_t_matrix::printMatrix() {
    signed long int r = row();
    signed long int c = col();

    for (signed long int i = 0; i < r; ++i) {
        for (signed long int j = 0; j < c; ++j) {
            if (c - 1 == j) {
                element_printf("%B\n", value[i][j]);
            } else {
                element_printf("%B ", value[i][j]);
            }
        }
    }
}

/**
 * get the row of the matrix
 * @return the row
 */
signed long int element_t_matrix::row() {
    return value.size();
}
/**
 * get the col of the matrix
 * @return the col
 */
signed long int element_t_matrix::col() {
    return value[0].size();
}

/**
 * get the element with the row index 'r' and the col index 'c'
 * @param r the row index
 * @param c the col index
 * @return the element
 */
element_s* element_t_matrix::getElement(signed long int r, signed long int c) {
    return value[r][c];
}
/**
 * set 'elem' to the element with the row index 'r' and the col index 'c'
 * @param r the row index
 * @param c the col index
 * @param elem 'elem'
 */
void element_t_matrix::setElement(signed long int r, signed long int c, element_s *elem) {
    element_set(value[r][c], elem);
}

/**
 * add '*v' to the end of the matrix as a row
 * @param v 'v'
 */
void element_t_matrix::pushBack(element_t_vector *v) {
    signed long int len = v->length();
    if (0 == len) {
        return;
    }

    element_s* sample_element = v->getElement(0);
    signed long int r = row();

    vector<element_s*> vv;

    for (signed long int i = 0; i < len; ++i) {
        element_t *initialization_element = new element_t[1];
        element_init_same_as(*initialization_element, sample_element);
        element_set(*initialization_element, v->getElement(i));
        vv.push_back(*initialization_element);
    }

    if (0 == r) {
        value.push_back(vv);
        return;
    }

    signed long int c = col();

    if (len == c) {
        value.push_back(vv);
    } else if (len < c) {
        for (signed long int i = 0; i < c - len; ++i) {
            element_t *initialization_element = new element_t[1];
            element_init_same_as(*initialization_element, sample_element);
            element_set0(*initialization_element);
            vv.push_back(*initialization_element);
        }
        value.push_back(vv);
    } else {
        for (signed long int rr = 0; rr < r; ++rr) {
            for (signed long int i = 0; i < len - c; ++i) {
                element_t *initialization_element = new element_t[1];
                element_init_same_as(*initialization_element, sample_element);
                element_set0(*initialization_element);
                value[rr].push_back(*initialization_element);
            }
        }
        value.push_back(vv);
    }
}