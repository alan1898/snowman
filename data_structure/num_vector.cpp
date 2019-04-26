//
// Created by alan on 19-4-26.
//

#include "num_vector.h"

num_vector::num_vector(signed long int len) {
    for (signed long int i = 0; i < len; ++i) {
        signed long int init_value = 0;
        value.push_back(init_value);
    }
}

void num_vector::printVector() {
    for (signed long int i = 0; i < length(); ++i) {
        if (length() - 1 == i) {
            cout << value[i] << endl;
        } else {
            cout << value[i] << " ";
        }
    }
}

signed long int num_vector::length() {
    return value.size();
}

signed long int num_vector::getElement(signed long int i) {
    return value[i];
}
void num_vector::setElement(signed long int i, signed long int elem) {
    value[i] = elem;
}

void num_vector::pushBack(signed long int elem) {
    value.push_back(elem);
}

void num_vector::resizeValue(signed long int i) {
    value.resize(i);
}