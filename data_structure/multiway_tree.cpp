//
// Created by alan on 19-4-26.
//

#include "multiway_tree.h"

multiway_tree_node::multiway_tree_node() {}
multiway_tree_node::multiway_tree_node(string name) {
    this->name.assign(name);

    parent = NULL;
    first_child = NULL;
    next_sibling = NULL;
}
multiway_tree_node::multiway_tree_node(element_s *sample_element) {
    this->name.assign("");

    element_init_same_as(this->value, sample_element);

    parent = NULL;
    first_child = NULL;
    next_sibling = NULL;
}
multiway_tree_node::multiway_tree_node(multiway_tree_node::node_type type, string name, signed long int threshold,
                                       element_s *sample_element) {
    this->type = type;

    this->name.assign(name);

    this->threshold = threshold;

    element_init_same_as(this->value, sample_element);

    this->parent = NULL;
    this->first_child = NULL;
    this->next_sibling = NULL;
}

multiway_tree_node::node_type multiway_tree_node::getType() {
    return type;
}
void multiway_tree_node::setType(multiway_tree_node::node_type type) {
    this->type = type;
}

string multiway_tree_node::getName() {
    return name;
}
void multiway_tree_node::setName(string name) {
    this->name.assign(name);
}

signed long int multiway_tree_node::getThreshold() {
    return threshold;
}
void multiway_tree_node::setThreshold(signed long int threshold) {
    this->threshold = threshold;
}

element_s* multiway_tree_node::getValue() {
    return value;
}
void multiway_tree_node::setValue(element_s *value) {
    element_set(this->value, value);
}

multiway_tree_node* multiway_tree_node::getParent() {
    return parent;
}
void multiway_tree_node::setParent(multiway_tree_node *parent) {
    this->parent = parent;
}
multiway_tree_node* multiway_tree_node::getFirstChild() {
    return first_child;
}
void multiway_tree_node::setFirstChild(multiway_tree_node *first_child) {
    this->first_child = first_child;
}
multiway_tree_node* multiway_tree_node::getNextSibling() {
    return next_sibling;
}
void multiway_tree_node::setNextSibling(multiway_tree_node *next_sibling) {
    this->next_sibling = next_sibling;
}

multiway_tree::multiway_tree(element_s *sample_element) {
    this->root = new multiway_tree_node(sample_element);
}
multiway_tree::multiway_tree(multiway_tree_node *root) {
    this->root = root;
}

multiway_tree_node* multiway_tree::getRoot() {
    return root;
}

void multiway_tree::visitNode(multiway_tree_node *node) {
    if (node->getType() == multiway_tree_node::LEAF) {
        cout << node->getName();
    } else if (node->getType() == multiway_tree_node::GATE) {
        cout << node->getThreshold();
    }
}

void multiway_tree::levelTraversal() {
    queue<multiway_tree_node*> q;

    multiway_tree_node *last = root;
    multiway_tree_node *nlast = root;

    q.push(root);

    while (!q.empty()) {
        visitNode(q.front());
        if (q.front()->getFirstChild() != NULL) {
            multiway_tree_node* child = q.front()->getFirstChild();
            while (NULL != child) {
                q.push(child);
                nlast = child;
                child = child->getNextSibling();
            }
        }
        if (q.front() == last) {
            cout << "|" << endl;
            last = nlast;
        } else if (q.front()->getNextSibling() == NULL){
            cout << "| ";
        } else {
            cout << "  ";
        }
        q.pop();
    }
}