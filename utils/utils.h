//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_UTILS_H
#define ABELIB_UTILS_H

#include "../basis.h"
#include "../data_structure/data_structure.h"
#include "../scheme_structure/scheme_structure.h"

class utils {
public:
    map<signed long int, signed long int>* attributesMatching(vector<string> *attributes, map<signed long int, string> *rho);

    element_t_matrix* getAttributesMatrix(element_t_matrix *M, map<signed long int, signed long int> *rho);

    element_t_matrix* inverse(element_t_matrix *M);

    element_t_vector* getCoordinateAxisUnitVector(element_t_matrix *M);

    map<signed long int, signed long int>* xToAttributes(element_t_matrix *M, map<signed long int, signed long int> *rho);

    // for SAR
//    sar_tree* generateEmptySarTreeFromOneSarTree(sar_tree *tree);
    void expandSarTree(sar_tree *tree);
    map<sar_tree_node*, bool>* sarKUNodes(sar_tree *tree);
    void sarRevock(string user_id, sar_kgc *kgc);
    void sarRevock(string user_id, string attribute, sar_kgc *kgc);
};


#endif //ABELIB_UTILS_H
