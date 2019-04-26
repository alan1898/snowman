//
// Created by alan on 19-4-26.
//

#include "abe_ciphertext.h"

abe_ciphertext::abe_ciphertext() {}
abe_ciphertext::abe_ciphertext(string policy, element_s *sample_element) {
    policy_resolution pr;
    policy_generation pg;

    vector<string>* postfix_expression = pr.infixToPostfix(policy);
    binary_tree* binary_tree_expression = pr.postfixToBinaryTree(postfix_expression, sample_element);

    pg.generatePolicyInMatrixForm(binary_tree_expression);

    M = pg.getPolicyInMatrixFormFromTree(binary_tree_expression);
    rho = pg.getRhoFromTree(binary_tree_expression);
}

void abe_ciphertext::setM(element_t_matrix *M) {
    this->M = M;
}
element_t_matrix* abe_ciphertext::getM() {
    return M;
}

void abe_ciphertext::setRho(map<signed long int, string> *rho) {
    this->rho = rho;
}
map<signed long int, string>* abe_ciphertext::getRho() {
    return rho;
}

element_s* abe_ciphertext::getComponent(string s) {
    map<string, element_s*>::iterator it;
    it = components.find(s);

    if (it == components.end()) {
        return NULL;
    } else {
        return (*it).second;
    }
}

void abe_ciphertext::insertComponent(string s, element_s *component) {
    element_t *insert_component = new element_t[1];
    element_init_same_as(*insert_component, component);
    element_set(*insert_component, component);
    components.insert(pair<string, element_s*>(s, *insert_component));
}

void abe_ciphertext::setT(multiway_tree *T) {
    this->T = T;
}
multiway_tree* abe_ciphertext::getT() {
    return T;
}