//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_MULTIWAY_TREE_H
#define ABELIB_MULTIWAY_TREE_H

#include "../basis.h"

class multiway_tree_node {
public:
    enum node_type { GATE, LEAF };
private:
    multiway_tree_node::node_type type;

    string name;
    signed long int threshold;
    element_t value;

    multiway_tree_node *parent;
    multiway_tree_node *first_child;
    multiway_tree_node *next_sibling;
public:
    multiway_tree_node();
    multiway_tree_node(string name);
    multiway_tree_node(element_s *sample_element);
    multiway_tree_node(multiway_tree_node::node_type type, string name, signed long int threshold, element_s *sample_element);

    multiway_tree_node::node_type getType();
    void setType(multiway_tree_node::node_type type);

    string getName();
    void setName(string name);

    signed long int getThreshold();
    void setThreshold(signed long int threshold);

    element_s* getValue();
    void setValue(element_s *value);

    multiway_tree_node* getParent();
    void setParent(multiway_tree_node *parent);
    multiway_tree_node* getFirstChild();
    void setFirstChild(multiway_tree_node *first_child);
    multiway_tree_node* getNextSibling();
    void setNextSibling(multiway_tree_node *next_sibling);
};

class multiway_tree {
private:
    multiway_tree_node *root;

    void visitNode(multiway_tree_node *node);
public:
    multiway_tree(element_s *sample_element);
    multiway_tree(multiway_tree_node *root);

    multiway_tree_node* getRoot();

    void levelTraversal();
};


#endif //ABELIB_MULTIWAY_TREE_H
