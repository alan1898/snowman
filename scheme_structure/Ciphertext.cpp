//
// Created by alan on 19-4-26.
//

#include "Ciphertext.h"

Ciphertext::Ciphertext() {
    g1_components = new map<string, element_s*>();
    g2_components = new map<string, element_s*>();
    gt_components = new map<string, element_s*>();
    zr_components = new map<string, element_s*>();
}
Ciphertext::Ciphertext(string policy) {
    this->policy = policy;

    g1_components = new map<string, element_s*>();
    g2_components = new map<string, element_s*>();
    gt_components = new map<string, element_s*>();
    zr_components = new map<string, element_s*>();
}
Ciphertext::Ciphertext(access_structure *A) {
    this->A = new access_structure(A->getID(), A->getM(), A->getRho(), A->getName());

    g1_components = new map<string, element_s*>();
    g2_components = new map<string, element_s*>();
    gt_components = new map<string, element_s*>();
    zr_components = new map<string, element_s*>();
}

access_structure* Ciphertext::getAccessStructure() {
    return A;
}

void Ciphertext::setPolicy(string policy) {
    this->policy = policy;
}
string Ciphertext::getPolicy() {
    return policy;
}

element_s* Ciphertext::getComponent(string s, string group) {
    map<string, element_s*>::iterator it;
    if (group == "G1") {
        it = g1_components->find(s);
        if (it == g1_components->end()) {
            return NULL;
        } else {
            return (*it).second;
        }
    } else if (group == "G2") {
        it = g2_components->find(s);
        if (it == g2_components->end()) {
            return NULL;
        } else {
            return (*it).second;
        }
    } else if (group == "GT") {
        it = gt_components->find(s);
        if (it == gt_components->end()) {
            return NULL;
        } else {
            return (*it).second;
        }
    } else if (group == "ZR") {
        it = zr_components->find(s);
        if (it == zr_components->end()) {
            return NULL;
        } else {
            return (*it).second;
        }
    }
}

void Ciphertext::insertComponent(string s, string group, element_s *component) {
    element_t *insert_component = new element_t[1];
    element_init_same_as(*insert_component, component);
    element_set(*insert_component, component);
    if (group == "G1") {
        g1_components->insert(pair<string, element_s*>(s, *insert_component));
    } else if (group == "G2") {
        g2_components->insert(pair<string, element_s*>(s, *insert_component));
    } else if (group == "GT") {
        gt_components->insert(pair<string, element_s*>(s, *insert_component));
    } else if (group == "ZR") {
        zr_components->insert(pair<string, element_s*>(s, *insert_component));
    }
}

map<string, element_s*>* Ciphertext::getComponents(string group) {
    if (group == "G1") {
        return g1_components;
    } else if (group == "G2") {
        return g2_components;
    } else if (group == "GT") {
        return gt_components;
    } else if (group == "ZR") {
        return zr_components;
    }
}

element_s* Ciphertext::getComponent(string s) {
    element_s *res;

    res = getComponent(s, "G1");
    if (res != NULL) {
        return res;
    }
    res = getComponent(s, "G2");
    if (res != NULL) {
        return res;
    }
    res = getComponent(s, "GT");
    if (res != NULL) {
        return res;
    }
    res = getComponent(s, "ZR");
    if (res != NULL) {
        return res;
    }

    return NULL;
}

void Ciphertext::printCiphertext() {
    cout << endl;
    cout << "policy: " << endl;
    cout << policy << endl;
    cout << endl;
    map<string, element_s*>::iterator it;
    cout << "G1: " << endl;
    for (it = g1_components->begin(); it != g1_components->end(); ++it) {
        cout << it->first << ": " << endl;
        element_printf("%B\n", it->second);
    }
    cout << endl;
    cout << "G2: " << endl;
    for (it = g2_components->begin(); it != g2_components->end(); ++it) {
        cout << it->first << ": " << endl;
        element_printf("%B\n", it->second);
    }
    cout << endl;
    cout << "GT: " << endl;
    for (it = gt_components->begin(); it != gt_components->end(); ++it) {
        cout << it->first << ": " << endl;
        element_printf("%B\n", it->second);
    }
    cout << endl;
    cout << "ZR: " << endl;
    for (it = zr_components->begin(); it != zr_components->end(); ++it) {
        cout << it->first << ": " << endl;
        element_printf("%B\n", it->second);
    }
    cout << endl;
}