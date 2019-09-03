//
// Created by alan on 19-8-30.
//

#include "access_structure.h"

access_structure::access_structure() {
    this->ID = new element_t_vector();
    this->M = new element_t_matrix();
    this->rho = new map<signed long int, string>();
    this->name = new string();
}

access_structure::access_structure(element_t_vector *ID, element_t_matrix *M, map<signed long int, string> *rho,
                                   string *name) {
    // 缺少合法判断
    this->ID = new element_t_vector(ID->length(), ID->getElement(0));

    this->M = new element_t_matrix(M->row(), M->col(), M->getElement(0, 0));

    this->rho = new map<signed long int, string>();

    this->name = new string();

    // copy ID
    for (signed long int i = 0; i < ID->length(); ++i) {
        this->ID->setElement(i, ID->getElement(i));
    }

    // copy M
    for (signed long int i = 0; i < M->row(); ++i) {
        for (signed long int j = 0; j < M->col(); ++j) {
            this->M->setElement(i, j, M->getElement(i, j));
        }
    }

    // copy rho
    map<signed long int, string>::iterator iterator1;
    for (iterator1 = rho->begin(); iterator1 != rho->end(); ++iterator1) {
        this->rho->insert(pair<signed long int, string>(iterator1->first, iterator1->second));
    }

    // copy name
    *(this->name) = *name;
}

element_t_vector* access_structure::getID() {
    return ID;
}

element_t_matrix* access_structure::getM() {
    return M;
}

map<signed long int, string>* access_structure::getRho() {
    return rho;
}

string* access_structure::getName() {
    return name;
}