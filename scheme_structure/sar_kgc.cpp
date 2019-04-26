//
// Created by alan on 19-4-26.
//

#include "sar_kgc.h"

sar_kgc::sar_kgc() {
    sar_tree_node *r = new sar_tree_node();
    sar_tree_node *r_lc = new sar_tree_node();
    sar_tree_node *r_rc = new sar_tree_node();

    r->setLeftChild(r_lc);
    r->setRightChild(r_rc);
    r_lc->setParent(r);
    r_rc->setParent(r);

    sar_tree *user_tree = new sar_tree();
    user_tree->setRoot(r);
    user_tree->getUndefinedLeaves()->push(r_lc);
    user_tree->getUndefinedLeaves()->push(r_rc);
    this->user_tree = user_tree;

    attribute_trees = new map<string, sar_tree*>();

    id_to_user_tree_node = new map<string, sar_tree_node*>();

    t = time(NULL);
}
sar_kgc::sar_kgc(signed long int user_tree_depth) {
    if (user_tree_depth <= 1) {
        return;
    }

    sar_tree_node *r = new sar_tree_node();

    queue<sar_tree_node*> q;

    q.push(r);

    signed long int last = 1;
    signed long int count = 1;
    signed long int d = 1;

    sar_tree *user_tree = new sar_tree();
    user_tree->setRoot(r);

    while (!q.empty()) {
        if (d < user_tree_depth) {
            sar_tree_node *lc = new sar_tree_node();
            sar_tree_node *rc = new sar_tree_node();

            q.front()->setLeftChild(lc);
            q.front()->setRightChild(rc);
            lc->setParent(q.front());
            rc->setParent(q.front());

            q.push(lc);
            q.push(rc);
        }
        if (d == user_tree_depth) {
            user_tree->getUndefinedLeaves()->push(q.front());
        }
        if (count == last) {
            count = 1;
            last = last * 2;
            ++d;
        } else {
            ++count;
        }
        q.pop();
    }
    this->user_tree = user_tree;

    attribute_trees = new map<string, sar_tree*>();

    id_to_user_tree_node = new map<string, sar_tree_node*>();

    t = time(NULL);
}

void sar_kgc::insertAttributeTree(string attribute) {
    sar_tree_node *r = new sar_tree_node();
    sar_tree_node *r_lc = new sar_tree_node();
    sar_tree_node *r_rc = new sar_tree_node();

    r->setLeftChild(r_lc);
    r->setRightChild(r_rc);
    r_lc->setParent(r);
    r_rc->setParent(r);

    sar_tree *attribute_tree = new sar_tree();
    attribute_tree->setRoot(r);
    attribute_tree->getUndefinedLeaves()->push(r_lc);
    attribute_tree->getUndefinedLeaves()->push(r_rc);

    map<string, sar_tree*>::iterator it = attribute_trees->find(attribute);
    if (it != attribute_trees->end()) {
        return;
    }
    attribute_trees->insert(pair<string, sar_tree*>(attribute, attribute_tree));
}
void sar_kgc::insertAttributeTree(string attribute, signed long int depth) {
    if (depth <= 1) {
        return;
    }

    sar_tree_node *r = new sar_tree_node();

    queue<sar_tree_node*> q;

    q.push(r);

    signed long int last = 1;
    signed long int count = 1;
    signed long int d = 1;

    sar_tree *attribute_tree = new sar_tree();
    attribute_tree->setRoot(r);

    while (!q.empty()) {
        if (d < depth) {
            sar_tree_node *lc = new sar_tree_node();
            sar_tree_node *rc = new sar_tree_node();

            q.front()->setLeftChild(lc);
            q.front()->setRightChild(rc);
            lc->setParent(q.front());
            rc->setParent(q.front());

            q.push(lc);
            q.push(rc);
        }
        if (d == depth) {
            attribute_tree->getUndefinedLeaves()->push(q.front());
        }
        if (count == last) {
            count = 1;
            last = last * 2;
            ++d;
        } else {
            ++count;
        }
        q.pop();
    }

    map<string, sar_tree*>::iterator it = attribute_trees->find(attribute);
    if (it != attribute_trees->end()) {
        return;
    }
    attribute_trees->insert(pair<string, sar_tree*>(attribute, attribute_tree));
}

sar_tree* sar_kgc::getUserTree() {
    return user_tree;
}

map<string, sar_tree*>* sar_kgc::getAttributeTrees() {
    return attribute_trees;
}
sar_tree* sar_kgc::getAttributeTree(string s) {
    map<string, sar_tree*>::iterator it;

    it = attribute_trees->find(s);

    if (it != attribute_trees->end()) {
        return it->second;
    } else {
        return NULL;
    }
}

map<string, sar_tree_node*>* sar_kgc::getIdToUserTreeNode() {
    return id_to_user_tree_node;
}
sar_tree_node* sar_kgc::getUserTreeNodeWithTheId(string id) {
    map<string, sar_tree_node*>::iterator it;
    it = id_to_user_tree_node->find(id);
    if (it != id_to_user_tree_node->end()) {
        return it->second;
    } else {
        return NULL;
    }
}
void sar_kgc::insertIdToUserTreeNode(string user_id, sar_tree_node *node) {
    map<string, sar_tree_node*>::iterator it = id_to_user_tree_node->find(user_id);
    if (it != id_to_user_tree_node->end()) {
        return;
    }
    id_to_user_tree_node->insert(pair<string, sar_tree_node*>(user_id, node));
}

void sar_kgc::setTToNowTime() {
    t = time(NULL);
}
char* sar_kgc::getTString() {
    return ctime(&t);
}