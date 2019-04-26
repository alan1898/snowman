//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_BINARY_TREE_H
#define ABELIB_BINARY_TREE_H

#include "../basis.h"
#include "element_t_vector.h"

class binary_tree_node {
public:
    enum node_type{ AND, OR, LEAF };
private:
    binary_tree_node::node_type type;

    string name;
    element_t_vector *value;

    binary_tree_node *parent;
    binary_tree_node *left_child;
    binary_tree_node *right_child;
public:
    binary_tree_node();
    binary_tree_node(element_s *sample_element);
    binary_tree_node(binary_tree_node::node_type type, string name, element_s *sample_element);

    binary_tree_node::node_type getType();
    void setType(binary_tree_node::node_type type);

    string getName();
    void setName(string name);

    element_t_vector* getValue();
    void setValue(element_t_vector *value);
    void pushBackValue(element_s *elem);
    element_s* getValueElement(signed long int i);
    void setValueElement(signed long int i, element_s *elem);
    void resizeValue(signed long int i);

    binary_tree_node* getParent();
    void setParent(binary_tree_node *parent);
    binary_tree_node* getLeftChild();
    void setLeftChild(binary_tree_node *left_child);
    binary_tree_node* getRightChild();
    void setRightChild(binary_tree_node *right_child);
};

class binary_tree {
private:
    binary_tree_node *root;

    void visitNode(binary_tree_node *node);

    void inOrderTraversalRoughly(binary_tree_node *node);
public:
    binary_tree(element_s *sample_element);
    binary_tree(binary_tree_node *root);

    binary_tree_node* getRoot();

    void levelTraversal();
    void inOrderTraversal();
};


#endif //ABELIB_BINARY_TREE_H
