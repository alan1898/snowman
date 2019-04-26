//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_ABE_CIPHERTEXT_H
#define ABELIB_ABE_CIPHERTEXT_H

#include "../basis.h"
#include "../data_structure/data_structure.h"
#include "../policy_resolution/policy_resolution.h"
#include "../policy_generation/policy_generation.h"

class abe_ciphertext {
private:
    map<string, element_s*> components;
    element_t_matrix* M;
    map<signed long int, string>* rho;

    multiway_tree *T;
public:
    abe_ciphertext();
    abe_ciphertext(string policy, element_s *sample_element);

    void setM(element_t_matrix* M);
    element_t_matrix* getM();

    void setRho(map<signed long int, string>* rho);
    map<signed long int, string>* getRho();

    element_s* getComponent(string s);
    void insertComponent(string s, element_s *component);

    void setT(multiway_tree *T);
    multiway_tree* getT();
};


#endif //ABELIB_ABE_CIPHERTEXT_H
