//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_POLICY_RESOLUTION_H
#define ABELIB_POLICY_RESOLUTION_H

#include "../basis.h"
#include "../data_structure/data_structure.h"

class policy_resolution {
public:
    vector<string>* infixToPostfix(string infix);
    binary_tree* postfixToBinaryTree(vector<string>* postfix, element_s *sample_element);

    multiway_tree* ThresholdExpressionToMultiwayTree(string threshold_expression, element_s *sample_element);
};


#endif //ABELIB_POLICY_RESOLUTION_H
