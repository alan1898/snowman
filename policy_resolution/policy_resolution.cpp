//
// Created by alan on 19-4-26.
//

#include "policy_resolution.h"

vector<string>* policy_resolution::infixToPostfix(string infix) {
    vector<string>* res = new vector<string>;

    signed long int len = infix.length();

    stack<char> st;

    string s = "";

    char oc;
    string os = "";

    for (signed long int i = 0; i < len; ++i) {
        char ch = infix.at(i);
        if ('&' == ch || '|' == ch || '(' == ch || ')' == ch) {
            if (0 != s.size()) {
                res->push_back(s);
                s.assign("");
            }
        } else if (len - 1 == i) {
            s.append(1, ch);
            res->push_back(s);
            break;
        }

        if ('&' == ch || '|' == ch || '(' == ch || ')' == ch) {
            if (st.empty() || '(' == ch || ('&' == ch && '|' == st.top())) {
                st.push(ch);
            } else if (')' == ch) {
                oc = st.top();
                st.pop();
                while ('(' != oc) {
                    os.assign(1, oc);
                    res->push_back(os);
                    oc = st.top();
                    st.pop();
                }
            } else {
                oc = st.top();
                while ((!('&' == ch && '|' == oc)) && '(' != oc) {
                    os.assign(1, oc);
                    res->push_back(os);
                    st.pop();
                    if (st.empty()) {
                        break;
                    }
                    oc = st.top();
                }
                st.push(ch);
            }
        } else {
            s.append(1, ch);
        }
    }

    while (!st.empty()) {
        oc = st.top();
        st.pop();
        os.assign(1, oc);
        res->push_back(os);
    }

    return res;
}

binary_tree* policy_resolution::postfixToBinaryTree(vector<string> *postfix, element_s *sample_element) {
    stack<binary_tree_node*> st;

    signed long int len = postfix->size();

    for (signed long int i = 0; i < len; ++i) {
        if ('&' == (*postfix)[i].at(0) || '|' == (*postfix)[i].at(0)) {
            binary_tree_node* node;
            if ('&' == (*postfix)[i].at(0)) {
                node = new binary_tree_node(binary_tree_node::AND, "", sample_element);
            } else {
                node = new binary_tree_node(binary_tree_node::OR, "", sample_element);
            }
            node->setRightChild(st.top());
            st.top()->setParent(node);
            st.pop();
            node->setLeftChild(st.top());
            st.top()->setParent(node);
            st.pop();
            st.push(node);
        } else {
            binary_tree_node* node = new binary_tree_node(binary_tree_node::LEAF, (*postfix)[i], sample_element);
            st.push(node);
        }
    }

    binary_tree* tree = new binary_tree(st.top());
    return tree;
}

multiway_tree* policy_resolution::ThresholdExpressionToMultiwayTree(string threshold_expression, element_s *sample_element) {
    stack<multiway_tree_node*> st;

    signed long int len = threshold_expression.length();

    string s;
    s.assign("");

    for (signed long int i = 0; i < len; ++i) {
        char ch = threshold_expression.at(i);
        if ('(' == ch) {
            multiway_tree_node* node = new multiway_tree_node("(");
            st.push(node);
        } else if (',' == ch) {
            if (0 == s.length()) {
                continue;
            } else {
                multiway_tree_node* node = new multiway_tree_node(multiway_tree_node::LEAF, s, 0, sample_element);
                st.push(node);
                s.assign("");
            }
        } else if (')' == ch) {
            signed long int threshold_value = 0;
            for (signed long int k = 0; k < s.length(); ++k) {
                signed long int n = s.length() - 1 - k;
                threshold_value += (s.at(n) - '0') * pow(double(10), double(k));
            }
            multiway_tree_node* node = new multiway_tree_node(multiway_tree_node::GATE, s, threshold_value, sample_element);
            s.assign("");

            multiway_tree_node* sibling = st.top();
            st.top()->setParent(node);
            st.pop();
            while (true) {
                if ('(' == st.top()->getName().at(0)) {
                    st.pop();
                    break;
                } else {
                    st.top()->setParent(node);
                    st.top()->setNextSibling(sibling);
                    sibling = st.top();
                    st.pop();
                }
            }
            node->setFirstChild(sibling);
            st.push(node);
        } else {
            s.append(1, ch);
        }
    }

    multiway_tree *tree = new multiway_tree(st.top());
    return tree;
}