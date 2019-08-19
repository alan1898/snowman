//
// Created by alan on 19-8-19.
//

#ifndef ABELIB_TEXT_H
#define ABELIB_TEXT_H

#include "../basis.h"
#include "../data_structure/data_structure.h"
#include "../policy_resolution/policy_resolution.h"
#include "../policy_generation/policy_generation.h"

class Text {
private:
    map<string, element_s*> *g1_components;
    map<string, element_s*> *g2_components;
    map<string, element_s*> *gt_components;
    map<string, element_s*> *zr_components;
public:
    Text();

    element_s* getComponent(string s, string group);
    void insertComponent(string s, string group, element_s *component);
    map<string, element_s*>* getComponents(string group);
    element_s* getComponent(string s);

    void printText();
};


#endif //ABELIB_TEXT_H
