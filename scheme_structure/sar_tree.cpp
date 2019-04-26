//
// Created by alan on 19-4-26.
//

#include "sar_tree.h"

sar_tree_node::sar_tree_node() {
    parent = NULL;
    left_child = NULL;
    right_child = NULL;

    user_id = "";

    value = new map<string, element_s*>();

    attribute_to_node = new map<string, sar_tree_node*>();

    has_defined_gx = false;

    has_been_revoked = false;
}
sar_tree_node::sar_tree_node(element_s *sample_element) {
    parent = NULL;
    left_child = NULL;
    right_child = NULL;

    user_id = "";

    value = new map<string, element_s*>();

    attribute_to_node = new map<string, sar_tree_node*>();

    element_init_same_as(gx, sample_element);

    has_defined_gx = false;

    has_been_revoked = false;
}

bool sar_tree_node::isLeaf() {
    if (NULL == left_child && NULL == right_child) {
        return true;
    } else {
        return false;
    }
}

sar_tree_node* sar_tree_node::getParent() {
    return parent;
}
void sar_tree_node::setParent(sar_tree_node *parent) {
    this->parent = parent;
}
sar_tree_node* sar_tree_node::getLeftChild() {
    return left_child;
}
void sar_tree_node::setLeftChild(sar_tree_node *left_child) {
    this->left_child = left_child;
}
sar_tree_node* sar_tree_node::getRightChild() {
    return right_child;
}
void sar_tree_node::setRightChild(sar_tree_node *right_child) {
    this->right_child = right_child;
}

string sar_tree_node::getUserId() {
    return user_id;
}
void sar_tree_node::setUserId(string user_id) {
    this->user_id = user_id;
}

map<string, element_s*>* sar_tree_node::getValue() {
    return value;
}
element_s* sar_tree_node::getValue(string s) {
    map<string, element_s*>::iterator it;
    it = value->find(s);

    if (it == value->end()) {
        return NULL;
    } else {
        return it->second;
    }
}
void sar_tree_node::insertValue(string s, element_s *e) {
    element_t *insert_e = new element_t[1];
    element_init_same_as(*insert_e, e);
    element_set(*insert_e, e);
    value->insert(pair<string, element_s*>(s, *insert_e));
}

map<string, sar_tree_node*>* sar_tree_node::getAttributeToNode() {
    return attribute_to_node;
}
sar_tree_node* sar_tree_node::getAttributeToNode(string s) {
    map<string, sar_tree_node*>::iterator it;
    it = attribute_to_node->find(s);
    if (it == attribute_to_node->end()) {
        return NULL;
    } else {
        return it->second;
    }
}
void sar_tree_node::insertAttributeToNode(string s, sar_tree_node *stn) {
    attribute_to_node->insert(pair<string, sar_tree_node*>(s, stn));
}

element_s* sar_tree_node::getGx() {
    return gx;
}
void sar_tree_node::setGx(element_s *elem) {
    element_init_same_as(gx, elem);
    element_set(gx, elem);
    has_defined_gx = true;
}
void sar_tree_node::randomGx(element_s *sample_element) {
    element_init_same_as(gx, sample_element);
    element_random(gx);
    has_defined_gx = true;
}
void sar_tree_node::randomGx() {
    element_random(gx);
    has_defined_gx = true;
}

bool sar_tree_node::gxIsDefined() {
    return has_defined_gx;
}
void sar_tree_node::defineGx() {
    has_defined_gx = true;
}

void sar_tree_node::revoke() {
    has_been_revoked = true;
}
bool sar_tree_node::isRevoked() {
    return has_been_revoked;
}

sar_tree::sar_tree() {
    undefined_leaves = new queue<sar_tree_node*>();

    revoked_leaves = new vector<sar_tree_node*>();
}

sar_tree_node* sar_tree::getRoot() {
    return root;
}
void sar_tree::setRoot(sar_tree_node *root) {
    this->root = root;
}

queue<sar_tree_node*>* sar_tree::getUndefinedLeaves() {
    return undefined_leaves;
}

vector<sar_tree_node*>* sar_tree::getRevokedLeaves() {
    return revoked_leaves;
}

void sar_tree_node::printNode() {
    if (isRevoked()) {
        cout << "N";
    } else {
        if (isLeaf()) {
            if (getUserId() == "") {
                cout << "E";
            } else {
                cout << getUserId();
            }
        } else {
            cout << "Y";
        }
    }
    if (gxIsDefined()) {
        cout << "(gx) ";
    } else {
        cout << "(no) ";
    }
}

void sar_tree::printSarTree() {
    queue<sar_tree_node*> q;

    q.push(root);

    signed long int last = 1;
    signed long int count = 1;

    while (!q.empty()) {
        q.front()->printNode();
        if (last == count) {
            cout << endl;
            last = last * 2;
            count = 1;
        } else {
            ++count;
        }
        if (q.front()->getLeftChild() != NULL) {
            q.push(q.front()->getLeftChild());
        }
        if (q.front()->getRightChild() != NULL) {
            q.push(q.front()->getRightChild());
        }
        q.pop();
    }
}