//
// Created by alan on 19-4-26.
//

#include "policy_generation.h"

void policy_generation::assignAccessToChildInMatrixForm(binary_tree_node *node, signed long int *m) {
    if (binary_tree_node::LEAF == node->getType()) {
        return;
    }

    binary_tree_node* lc = node->getLeftChild();
    binary_tree_node* rc = node->getRightChild();

    if (binary_tree_node::OR == node->getType()) {
        lc->setValue(node->getValue());
        rc->setValue(node->getValue());
        return;
    }

    element_t zero;
    element_t one;
    element_t negOne;
    element_init_same_as(zero, node->getValueElement(0));
    element_init_same_as(one, zero);
    element_init_same_as(negOne, zero);
    element_set0(zero);
    element_set1(one);
    element_set_si(negOne, -1);
    signed long int len = node->getValue()->length();

    if (binary_tree_node::AND == node->getType()) {
        if (len < *m) {
            for (signed long int i = 0; i < (*m) - len; ++i) {
                node->pushBackValue(zero);
            }
        }
        lc->setValue(node->getValue());
        rc->resizeValue(0);
        for (signed long int i = 0; i < *m; ++i) {
            rc->pushBackValue(zero);
        }
        lc->pushBackValue(one);
        rc->pushBackValue(negOne);
        (*m)++;
        return;
    }
}

void policy_generation::assignAccessToChildInBinaryTreeForm(binary_tree_node *node) {
    if (binary_tree_node::LEAF == node->getType()) {
        return;
    }

    binary_tree_node* lc = node->getLeftChild();
    binary_tree_node* rc = node->getRightChild();

    if (binary_tree_node::OR == node->getType()) {
        lc->setValueElement(0, node->getValueElement(0));
        rc->setValueElement(0, node->getValueElement(0));
        return;
    }

    element_t node_secret;
    element_init_same_as(node_secret, node->getValueElement(0));
    element_set(node_secret, node->getValueElement(0));

    element_t one;
    element_init_same_as(one, node_secret);
    element_set1(one);
    element_t two;
    element_init_same_as(two, node_secret);
    element_set_si(two, 2);

    element_t res1;
    element_init_same_as(res1, node_secret);
    element_set(res1, node_secret);
    element_t res2;
    element_init_same_as(res2, node_secret);
    element_set(res2, node_secret);

    element_t r;
    element_init_same_as(r, node_secret);
    while (element_is0(r)) {
        element_random(r);
    }

    element_printf("the coefficient is %B\n", r);

    element_t mul1;
    element_init_same_as(mul1, node_secret);
    element_mul(mul1, r, one);
    element_add(res1, res1, mul1);

    element_t mul2;
    element_init_same_as(mul2, node_secret);
    element_mul(mul2, r, two);
    element_add(res2, res2, mul2);

    if (binary_tree_node::AND == node->getType()) {
        lc->setValueElement(0, res1);
        rc->setValueElement(0, res2);
        return;
    }
}

void policy_generation::assignAccessToChildInMultiwayTreeForm(multiway_tree_node *node) {
    if (multiway_tree_node::LEAF == node->getType()) {
        return;
    }

    multiway_tree_node* child = node->getFirstChild();

    signed long int serial_number = 1;
    element_t serial_element;
    element_init_same_as(serial_element, node->getValue());
    element_t serial_pow;
    element_init_same_as(serial_pow, node->getValue());
    element_t serial_mul;
    element_init_same_as(serial_mul, node->getValue());

    element_t_vector random_coefficient(node->getThreshold() - 1, node->getValue());
    for (signed long int i = 0; i < random_coefficient.length(); ++i) {
        element_random(random_coefficient.getElement(i));
    }
    if (node->getThreshold() > 1) {
        while (element_is0(random_coefficient.getElement(random_coefficient.length() - 1))) {
            element_random(random_coefficient.getElement(random_coefficient.length() - 1));
        }
    }

//    element_printf("random coefficient: ");
//    if (node->getThreshold() == 1) {
//        element_printf("\n");
//    }
//    random_coefficient.printVector();

    while (NULL != child) {
        element_t *serial_res = new element_t[1];
        element_init_same_as(*serial_res, node->getValue());
        element_set_si(serial_element, serial_number);
        element_set(*serial_res, node->getValue());
        for (signed long int i = 0; i < random_coefficient.length(); ++i) {
            element_set(serial_pow, serial_element);
            for (signed long int j = 0; j < i; ++j) {
                element_mul(serial_pow, serial_pow, serial_element);
            }
            element_mul(serial_mul, random_coefficient.getElement(i), serial_pow);
            element_add(*serial_res, *serial_res, serial_mul);
        }
        child->setValue(*serial_res);
        child = child->getNextSibling();
        serial_number++;
    }
}

void policy_generation::generatePolicyInMatrixForm(binary_tree *tree) {
    signed long int *m = new signed long int;
    *m = 1;

    queue<binary_tree_node*> q;

    q.push(tree->getRoot());

    while (!q.empty()) {
        assignAccessToChildInMatrixForm(q.front(), m);
        if (q.front()->getLeftChild() != NULL) {
            q.push(q.front()->getLeftChild());
        }
        if (q.front()->getRightChild() != NULL) {
            q.push(q.front()->getRightChild());
        }
        q.pop();
    }
}

element_t_matrix* policy_generation::getPolicyInMatrixFormFromTree(binary_tree *tree) {
    element_t_matrix* res = new element_t_matrix();

    queue<binary_tree_node*> q;

    q.push(tree->getRoot());

    while (!q.empty()) {
        if (q.front()->getType() == binary_tree_node::LEAF) {
            element_t_vector v(*(q.front()->getValue()));
            res->pushBack(&v);
        }
        if (q.front()->getLeftChild() != NULL) {
            q.push(q.front()->getLeftChild());
        }
        if (q.front()->getRightChild() != NULL) {
            q.push(q.front()->getRightChild());
        }
        q.pop();
    }

    return res;
}

map<signed long int, string>* policy_generation::getRhoFromTree(binary_tree *tree) {
    map<signed long int, string> *res = new map<signed long int, string>;

    signed long int kk = 0;

    queue<binary_tree_node*> q;

    q.push(tree->getRoot());

    while (!q.empty()) {
        if (q.front()->getType() == binary_tree_node::LEAF) {
            signed long int k = kk;
            string v = "";
            v.assign(q.front()->getName());
            res->insert(pair<signed long int, string>(k, v));
            ++kk;
        }
        if (q.front()->getLeftChild() != NULL) {
            q.push(q.front()->getLeftChild());
        }
        if (q.front()->getRightChild() != NULL) {
            q.push(q.front()->getRightChild());
        }
        q.pop();
    }

    return res;
}

void policy_generation::generatePolicyInBinaryTreeForm(binary_tree *tree, element_s *root_secret) {
    tree->getRoot()->setValueElement(0, root_secret);

    queue<binary_tree_node*> q;

    q.push(tree->getRoot());

    while (!q.empty()) {
        assignAccessToChildInBinaryTreeForm(q.front());
        if (q.front()->getLeftChild() != NULL) {
            q.push(q.front()->getLeftChild());
        }
        if (q.front()->getRightChild() != NULL) {
            q.push(q.front()->getRightChild());
        }
        q.pop();
    }
}

element_t_vector* policy_generation::getPolicyInBinaryTreeFormFromTree(binary_tree *tree) {
    element_t_vector* res = new element_t_vector();

    queue<binary_tree_node*> q;

    q.push(tree->getRoot());

    while (!q.empty()) {
        if (q.front()->getType() == binary_tree_node::LEAF) {
            res->pushBack(q.front()->getValueElement(0));
        }
        if (q.front()->getLeftChild() != NULL) {
            q.push(q.front()->getLeftChild());
        }
        if (q.front()->getRightChild() != NULL) {
            q.push(q.front()->getRightChild());
        }
        q.pop();
    }

    return res;
}

void policy_generation::generatePolicyInMultiwayTreeForm(multiway_tree *tree, element_s *root_secret) {
    tree->getRoot()->setValue(root_secret);

    queue<multiway_tree_node*> q;

    q.push(tree->getRoot());

    while (!q.empty()) {
        assignAccessToChildInMultiwayTreeForm(q.front());
        if (q.front()->getFirstChild() != NULL) {
            multiway_tree_node* child = q.front()->getFirstChild();
            while (NULL != child) {
                q.push(child);
                child = child->getNextSibling();
            }
        }
        q.pop();
    }
}

map<string, element_s*>* policy_generation::getSharesFromTree(multiway_tree *tree) {
    map<string, element_s*> *res = new map<string, element_s*>();

    queue<multiway_tree_node*> q;

    q.push(tree->getRoot());

    while (!q.empty()) {
        if (q.front()->getType() == multiway_tree_node::LEAF) {
            element_t *insert_component = new element_t[1];
            element_init_same_as(*insert_component, q.front()->getValue());
            element_set(*insert_component, q.front()->getValue());
            res->insert(pair<string, element_s*>(q.front()->getName(), *insert_component));
        }
        if (q.front()->getFirstChild() != NULL) {
            multiway_tree_node* child = q.front()->getFirstChild();
            while (NULL != child) {
                q.push(child);
                child = child->getNextSibling();
            }
        }
        q.pop();
    }

    return res;
}

//element_t_matrix* policy_generation::generateLSSSMatrixFromThresholdExpression(string threshold_expression,
//                                                                               element_s *sample_element) {
//    element_t_matrix *res = new element_t_matrix(1, 1, sample_element);
//    element_set1(res->getElement(0, 0));
//    vector<string> L(1);
//    L[1] = threshold_expression;
//
//    vector<string>::iterator iterator1;
//    while (1) {
//        for (iterator1 = L.begin(); iterator1 != L.end(); ++iterator1) {
//            if ((*iterator1).at(0) == '(') {
//                for (signed long int i = 1; i < (*iterator1).size() - 1; ++i) {
//                    //
//                }
//                break;
//            }
//        }
//        if (iterator1 == L.end()) {
//            break;
//        }
//    }
//    return res;
//}

element_t_matrix* policy_generation::generateLSSSMatrixFromMultiwayTree(multiway_tree *mt, element_s *sample_element) {
    element_t_matrix *res = new element_t_matrix(1, 1, sample_element);
    element_set1(res->getElement(0, 0));
    vector<multiway_tree_node*> L(1);
    L[0] = mt->getRoot();
    signed long int pre_col = res->col();

    signed long int i;
    while (1) {
        for (i = 0; i < L.size(); ++i) {
            multiway_tree_node *split = L[i];
            if (split->getType() == multiway_tree_node::GATE) {
                signed long int threshold = split->getThreshold();
                element_t_vector vv;
                for (signed long int m = 0; m < res->col(); ++m) {
                    element_t *initialization_element = new element_t[1];
                    element_init_same_as(*initialization_element, sample_element);
                    element_set(*initialization_element, res->getElement(i, m));
                    vv.pushBack(*initialization_element);
                }
                for (signed long int m = 0; m < threshold - 1; ++m) {
                    element_t *initialization_element = new element_t[1];
                    element_init_same_as(*initialization_element, sample_element);
                    element_set0(*initialization_element);
                    vv.pushBack(*initialization_element);
                }

                L[i] = split->getFirstChild();
                signed long int new_row = 0;
                if (i == L.size() - 1) {
                    multiway_tree_node *child = split->getFirstChild()->getNextSibling();
                    while (child != NULL) {
                        res->pushBack(&vv);
                        ++new_row;

                        multiway_tree_node **insert_child = new multiway_tree_node*[1];
                        (*insert_child) = child;
                        L.push_back(*insert_child);
                        child = child->getNextSibling();
                    }
                } else {
                    multiway_tree_node *child = split->getFirstChild()->getNextSibling();
                    int j = 1;
                    while (child != NULL) {
                        res->pushBack(&vv, i);
                        ++new_row;

                        multiway_tree_node **insert_child = new multiway_tree_node*[1];
                        (*insert_child) = child;
                        L.insert(L.begin() + i + j, *insert_child);
                        child = child->getNextSibling();
                        ++j;
                    }
                }

                for (signed long int n_c = 0; n_c < threshold - 1; ++n_c) {
                    for (signed long int n_r = 0; n_r < new_row + 1; ++n_r) {
                        element_t base;
                        element_init_same_as(base, sample_element);
                        element_set_si(base, n_r + 1);
                        element_t pow;
                        element_init_same_as(pow, sample_element);
                        element_set_si(pow, n_c + 1);
                        element_t base_pow;
                        element_init_same_as(base_pow, sample_element);
                        element_pow_zn(base_pow, base, pow);
                        res->setElement(i + n_r, pre_col + n_c, base_pow);
                    }
                }
                pre_col = res->col();

                break;
            }
        }
        if (i == L.size()) {
            break;
        }
    }

    for (signed long int m = 0; m < L.size(); ++m) {
        cout << L[m]->getName() << " ";
    }
    cout << endl;

    return res;
}