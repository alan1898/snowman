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