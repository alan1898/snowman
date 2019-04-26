//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_SAR_TREE_H
#define ABELIB_SAR_TREE_H

#include "../basis.h"

class sar_tree_node {
private:
    sar_tree_node *parent;
    sar_tree_node *left_child;
    sar_tree_node *right_child;

    string user_id;

    map<string, element_s*> *value;

    map<string, sar_tree_node*> *attribute_to_node;

    element_t gx;
    bool has_defined_gx;

    bool has_been_revoked;
public:
    sar_tree_node();
    sar_tree_node(element_s *sample_element);

    bool isLeaf();

    sar_tree_node* getParent();
    void setParent(sar_tree_node *parent);
    sar_tree_node* getLeftChild();
    void setLeftChild(sar_tree_node *left_child);
    sar_tree_node* getRightChild();
    void setRightChild(sar_tree_node *right_child);

    string getUserId();
    void setUserId(string user_id);

    map<string, element_s*>* getValue();
    element_s* getValue(string s);
    void insertValue(string s, element_s *e);

    map<string, sar_tree_node*>* getAttributeToNode();
    sar_tree_node* getAttributeToNode(string s);
    void insertAttributeToNode(string s, sar_tree_node *stn);

    element_s* getGx();
    void setGx(element_s *elem);
    void randomGx(element_s *sample_element);
    void randomGx();
    void defineGx();

    bool gxIsDefined();

    void revoke();
    bool isRevoked();

    void printNode();
};

class sar_tree {
private:
    sar_tree_node *root;

    queue<sar_tree_node*> *undefined_leaves;

    vector<sar_tree_node*> *revoked_leaves;

public:
    sar_tree();

    sar_tree_node* getRoot();
    void setRoot(sar_tree_node *root);

    queue<sar_tree_node*>* getUndefinedLeaves();

    vector<sar_tree_node*>* getRevokedLeaves();

    void printSarTree();
};

#endif //ABELIB_SAR_TREE_H
