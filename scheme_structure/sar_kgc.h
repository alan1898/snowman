//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_SAR_KGC_H
#define ABELIB_SAR_KGC_H

#include "../basis.h"
#include "sar_tree.h"

class sar_kgc {
private:
    sar_tree *user_tree;
    map<string, sar_tree*> *attribute_trees;
    map<string, sar_tree_node*> *id_to_user_tree_node;

    time_t t;
public:
    sar_kgc();
    sar_kgc(signed long int user_tree_depth);

    sar_tree* getUserTree();

    void insertAttributeTree(string attribute);
    void insertAttributeTree(string attribute, signed long int depth);
    map<string, sar_tree*>* getAttributeTrees();
    sar_tree* getAttributeTree(string s);

    map<string, sar_tree_node*>* getIdToUserTreeNode();
    sar_tree_node* getUserTreeNodeWithTheId(string id);
    void insertIdToUserTreeNode(string user_id, sar_tree_node *node);

    void setTToNowTime();
    char* getTString();
};


#endif //ABELIB_SAR_KGC_H
