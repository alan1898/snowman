//
// Created by alan on 19-4-26.
//

#include "binary_tree.h"

/**
 * constructor
 */
binary_tree_node::binary_tree_node() {}
binary_tree_node::binary_tree_node(element_s *sample_element) {
    this->name.assign("");

    value = new element_t_vector(1, sample_element);
    element_set1(value->getElement(0));

    parent = NULL;
    left_child = NULL;
    right_child = NULL;
}
binary_tree_node::binary_tree_node(binary_tree_node::node_type type, string name, element_s *sample_element) {
    this->type = type;

    this->name.assign(name);

    value = new element_t_vector(1, sample_element);
    element_set1(value->getElement(0));

    parent = NULL;
    left_child = NULL;
    right_child = NULL;
}

/**
 * get the type of the node
 * @return node type
 */
binary_tree_node::node_type binary_tree_node::getType() {
    return type;
}
/**
 * set the type of the node
 * @param type node type
 */
void binary_tree_node::setType(binary_tree_node::node_type type) {
    this->type = type;
}

/**
 * get the name of the node
 * @return node name
 */
string binary_tree_node::getName() {
    return name;
}
/**
 * set the name of the node
 * @param name node name
 */
void binary_tree_node::setName(string name) {
    this->name.assign(name);
}

/**
 * get the value of the node
 * @return node value
 */
element_t_vector* binary_tree_node::getValue() {
    return value;
}
/**
 * set the value of the node
 * @param value node value
 */
void binary_tree_node::setValue(element_t_vector *value) {
    *(this->value) = *value;
}
/**
 * add 'elem' to the end of the value vector
 * @param elem 'elem'
 */
void binary_tree_node::pushBackValue(element_s *elem) {
    value->pushBack(elem);
}
/**
 * get the element with the index 'i'
 * @param i the index
 * @return the element
 */
element_s* binary_tree_node::getValueElement(signed long int i) {
    return value->getElement(i);
}
void binary_tree_node::setValueElement(signed long int i, element_s *elem) {
    value->setElement(i, elem);
}
/**
 * resize value
 * @param i the new size
 */
void binary_tree_node::resizeValue(signed long int i) {
    value->resizeValue(i);
}

/**
 * get parent
 * @return parent
 */
binary_tree_node* binary_tree_node::getParent() {
    return parent;
}
/**
 * set parent
 * @param parent parent
 */
void binary_tree_node::setParent(binary_tree_node *parent) {
    this->parent = parent;
}
/**
 * get left child
 * @return left child
 */
binary_tree_node* binary_tree_node::getLeftChild() {
    return left_child;
}
/**
 * set left child
 * @param left_child left child
 */
void binary_tree_node::setLeftChild(binary_tree_node *left_child) {
    this->left_child = left_child;
}
/**
 * get right child
 * @return right child
 */
binary_tree_node* binary_tree_node::getRightChild() {
    return right_child;
}
/**
 * set right child
 * @param right_child right child
 */
void binary_tree_node::setRightChild(binary_tree_node *right_child) {
    this->right_child = right_child;
}

/**
 * constructor
 */
binary_tree::binary_tree(element_s *sample_element) {
    root = new binary_tree_node(sample_element);
}
binary_tree::binary_tree(binary_tree_node *root) {
    this->root = root;
}

/**
 * get root
 * @return root
 */
binary_tree_node* binary_tree::getRoot() {
    return root;
}

/**
 * print node
 * @param node the node
 */
void binary_tree::visitNode(binary_tree_node *node) {
    if (node->getType() == binary_tree_node::LEAF) {
        cout << node->getName();
    } else if (node->getType() == binary_tree_node::AND) {
        cout << "AND";
    } else if (node->getType() == binary_tree_node::OR) {
        cout << "OR";
    }
}

/**
 * in order recursive traversal
 * @param node the current node
 */
void binary_tree::inOrderTraversalRoughly(binary_tree_node *node) {
    if (node == NULL) {
        return;
    }
    inOrderTraversalRoughly(node->getLeftChild());
    visitNode(node);
    cout << "  ";
    inOrderTraversalRoughly(node->getRightChild());
}

/**
 * level traversal, print by layer newline
 */
void binary_tree::levelTraversal() {
    queue<binary_tree_node*> q;

    binary_tree_node *last = root;
    binary_tree_node *nlast = root;

    q.push(root);

    while (!q.empty()) {
        visitNode(q.front());
        if (q.front()->getLeftChild() != NULL) {
            q.push(q.front()->getLeftChild());
            nlast = q.front()->getLeftChild();
        }
        if (q.front()->getRightChild() != NULL) {
            q.push(q.front()->getRightChild());
            nlast = q.front()->getRightChild();
        }
        if (q.front() == last) {
            cout << endl;
            last = nlast;
        } else {
            cout << "  ";
        }
        q.pop();
    }
}
/**
 * in order traversal
 */
void binary_tree::inOrderTraversal() {
    inOrderTraversalRoughly(root);
    cout << endl;
}