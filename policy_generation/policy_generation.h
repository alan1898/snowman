//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_POLICY_GENERATION_H
#define ABELIB_POLICY_GENERATION_H

#include "../basis.h"
#include "../data_structure/data_structure.h"

class policy_generation {
private:
    void assignAccessToChildInMatrixForm(binary_tree_node *node, signed long int *m);

    void assignAccessToChildInBinaryTreeForm(binary_tree_node *node);

    void assignAccessToChildInMultiwayTreeForm(multiway_tree_node *node);
public:
    void generatePolicyInMatrixForm(binary_tree *tree);
    element_t_matrix* getPolicyInMatrixFormFromTree(binary_tree *tree);
    map<signed long int, string>* getRhoFromTree(binary_tree *tree);


    void generatePolicyInBinaryTreeForm(binary_tree *tree, element_s *root_secret);
    element_t_vector* getPolicyInBinaryTreeFormFromTree(binary_tree *tree);

    void generatePolicyInMultiwayTreeForm(multiway_tree *tree, element_s *root_secret);
    map<string, element_s*>* getSharesFromTree(multiway_tree *tree);
};


#endif //ABELIB_POLICY_GENERATION_H
