//
// Created by alan on 19-4-26.
//

#include "utils.h"

map<signed long int, signed long int>* utils::attributesMatching(vector<string> *attributes,
                                                                 map<signed long int, string> *rho) {
    map<signed long int, signed long int> *res = new map<signed long int, signed long int>;

    for (signed long int i = 0; i < attributes->size(); ++i){
        map<signed long int, string>::iterator it;
        for (it = rho->begin(); it != rho->end(); ++it) {
            if ((*attributes)[i] == it->second) {
                res->insert(pair<signed long int, signed long int>(it->first, i));
            }
        }
    }

    return res;
}

element_t_matrix* utils::getAttributesMatrix(element_t_matrix *M, map<signed long int, signed long int> *rho) {
    if (0 == M->row() || 0 == M->col()) {
        return NULL;
    }

    element_t_matrix *res = new element_t_matrix();

    for (signed long int i = 0; i < M->row(); ++i) {
        map<signed long int, signed long int>::iterator it = rho->find(i);
        if (it != rho->end()) {
            element_t_vector *v = new element_t_vector();
            for (signed long int j = 0; j < M->col(); ++j) {
                v->pushBack(M->getElement(i, j));
            }
            res->pushBack(v);
        }
    }

    return res;
}

element_t_matrix* utils::inverse(element_t_matrix *M) {
    if (0 == M->row() || 0 == M->col()) {
        return NULL;
    }

    element_t_matrix *res = new element_t_matrix(M->col(), M->row(), M->getElement(0, 0));

    for (signed long int i = 0; i < M->row(); ++i) {
        for (signed long int j = 0; j < M->col(); ++j) {
            element_set(res->getElement(j, i), M->getElement(i, j));
        }
    }

    return res;
}

element_t_vector* utils::getCoordinateAxisUnitVector(element_t_matrix *M) {
    if (0 == M->row() || 0 == M->col()) {
        return NULL;
    }

    element_t_vector *res = new element_t_vector(M->row(), M->getElement(0, 0));

    element_set1(res->getElement(0));
    for (signed long int i = 1; i < res->length(); ++i) {
        element_set0(res->getElement(i));
    }

    return res;
}

map<signed long int, signed long int>* utils::xToAttributes(element_t_matrix *M,
                                                            map<signed long int, signed long int> *rho) {
    if (0 == M->row() || 0 == M->col()) {
        return NULL;
    }

    signed long int k = 0;

    map<signed long int, signed long int> *res = new map<signed long int, signed long int>;
    for (signed long int i = 0; i < M->row(); ++i) {
        map<signed long int, signed long int>::iterator it = rho->find(i);
        if (it != rho->end()) {
            res->insert(pair<signed long int, signed long int>(it->second, k));
            ++k;
        }
    }

    return res;
}

//sar_tree* utils::generateEmptySarTreeFromOneSarTree(sar_tree *tree) {
//    queue<sar_tree_node*> q;
//    map<sar_tree_node*, sar_tree_node*> m;
//
//    sar_tree_node *r = new sar_tree_node();
//
//    q.push(tree->getRoot());
//    m.insert(pair<sar_tree_node*, sar_tree_node*>(tree->getRoot(), r));
//    map<sar_tree_node*, sar_tree_node*>::iterator it;
//
//    while (!q.empty()) {
//        it = m.find(q.front());
//        if (q.front()->getLeftChild() != NULL) {
//            sar_tree_node *lc = new sar_tree_node();
//            it->second->setLeftChild(lc);
//            lc->setParent(it->second);
//            m.insert(pair<sar_tree_node*, sar_tree_node*>(q.front()->getLeftChild(), lc));
//        }
//        if (q.front()->getRightChild() != NULL) {
//            sar_tree_node *rc = new sar_tree_node();
//            it->second->setRightChild(rc);
//            rc->setParent(it->second);
//            m.insert(pair<sar_tree_node*, sar_tree_node*>(q.front()->getRightChild(), rc));
//        }
//        q.pop();
//    }
//
//    sar_tree *res = new sar_tree();
//    it = m.find(tree->getRoot());
//    res->setRoot(it->second);
//
//    return res;
//}
//
//void utils::expandSarTree(sar_tree *tree) {
//    sar_tree *new_part = generateEmptySarTreeFromOneSarTree(tree);
//
//    sar_tree_node *new_root = new sar_tree_node();
//
//    new_root->setLeftChild(tree->getRoot());
//    new_root->setRightChild(new_part->getRoot());
//    tree->getRoot()->setParent(new_root);
//    new_part->getRoot()->setParent(new_root);
//
//    if (tree->getRoot()->isRevoked()) {
//        new_root->revoke();
//    }
//
//    tree->setRoot(new_root);
//}

void utils::expandSarTree(sar_tree *tree) {
    queue<sar_tree_node*> q;
    map<sar_tree_node*, sar_tree_node*> m;

    sar_tree_node *r = new sar_tree_node();

    q.push(tree->getRoot());
    m.insert(pair<sar_tree_node*, sar_tree_node*>(tree->getRoot(), r));
    map<sar_tree_node*, sar_tree_node*>::iterator it;

    while (!q.empty()) {
        it = m.find(q.front());
        if (q.front()->getLeftChild() != NULL) {
            sar_tree_node *lc = new sar_tree_node();
            it->second->setLeftChild(lc);
            lc->setParent(it->second);
            m.insert(pair<sar_tree_node*, sar_tree_node*>(q.front()->getLeftChild(), lc));
        }
        if (q.front()->getRightChild() != NULL) {
            sar_tree_node *rc = new sar_tree_node();
            it->second->setRightChild(rc);
            rc->setParent(it->second);
            m.insert(pair<sar_tree_node*, sar_tree_node*>(q.front()->getRightChild(), rc));
        }
        if (q.front()->isLeaf()) {
            tree->getUndefinedLeaves()->push(it->second);
        }
        q.pop();
    }

    sar_tree *new_part = new sar_tree();
    it = m.find(tree->getRoot());
    new_part->setRoot(it->second);

    sar_tree_node *new_root = new sar_tree_node();

    new_root->setLeftChild(tree->getRoot());
    new_root->setRightChild(new_part->getRoot());
    tree->getRoot()->setParent(new_root);
    new_part->getRoot()->setParent(new_root);

    if (tree->getRoot()->isRevoked()) {
        new_root->revoke();
    }

    tree->setRoot(new_root);
}

map<sar_tree_node*, bool>* utils::sarKUNodes(sar_tree *tree) {
    vector<sar_tree_node*> *rl = tree->getRevokedLeaves();

    map<sar_tree_node*, bool> *res = new map<sar_tree_node*, bool>();

    for (signed long int i = 0; i < rl->size(); ++i) {
        sar_tree_node *p = (*rl)[i];
        while (NULL != p) {
            if ((NULL != p->getLeftChild()) && (!p->getLeftChild()->isRevoked())) {
                map<sar_tree_node*, bool>::iterator it = res->find(p->getLeftChild());
                if (res->end() == it) {
                    res->insert(pair<sar_tree_node*, bool>(p->getLeftChild(), true));
                }
            }
            if ((NULL != p->getRightChild()) && (!p->getRightChild()->isRevoked())) {
                map<sar_tree_node*, bool>::iterator it = res->find(p->getRightChild());
                if (res->end() == it) {
                    res->insert(pair<sar_tree_node*, bool>(p->getRightChild(), true));
                }
            }
            p = p->getParent();
        }
    }

    if (res->empty()) {
        res->insert(pair<sar_tree_node*, bool>(tree->getRoot(), true));
    }

    return res;
}

void utils::sarRevock(string user_id, sar_kgc *kgc) {
    sar_tree_node *user_tree_node = kgc->getUserTreeNodeWithTheId(user_id);

    sar_tree_node *p = user_tree_node;
    while (p != NULL) {
        p->revoke();
        p = p->getParent();
    }

    kgc->getUserTree()->getRevokedLeaves()->push_back(user_tree_node);
}
void utils::sarRevock(string user_id, string attribute, sar_kgc *kgc) {
    sar_tree_node *user_tree_node = kgc->getUserTreeNodeWithTheId(user_id);

    sar_tree_node *user_attribute_tree_node = user_tree_node->getAttributeToNode(attribute);

    sar_tree_node *p = user_attribute_tree_node;

    while (p != NULL) {
        p->revoke();
        p = p->getParent();
    }
}