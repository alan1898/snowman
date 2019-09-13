//
// Created by alan on 19-9-14.
//

#include "BCET_test.h"

BCET_test::BCET_test() {
    // init pairing
    pbc_param_t par;
    curve_param curves;
    pbc_param_init_set_str(par, curves.a_param.c_str());
    pairing_init_pbc_param(pairing, par);
}

void BCET_test::setup_test(signed long int num) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        BCET *bcet = new BCET();
        bcet->setUp();
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", Setup: " << execution_time << "ms" << endl;
}

void BCET_test::keygen_test(signed long int num) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    vector<string> *attributes = new vector<string>();
    char n[4];
    for (signed long int i = 100; i <= 100 + num; ++i) {
        sprintf(n, "%ld", i);
        attributes->push_back(n);
    }

    BCET bcet;

    // set up
    vector<Key*> *psk = bcet.setUp();

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        bcet.keyGen(psk->at(1), psk->at(0), attributes);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", KeyGen: " << execution_time << "ms" << endl;
}

void BCET_test::encrypt_test(signed long int num) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    vector<string> *attributes = new vector<string>();
    char n[4];
    for (signed long int i = 100; i <= 100 + num; ++i) {
        sprintf(n, "%ld", i);
        attributes->push_back(n);
    }

    string policy = "";
    for (signed long int i = 0; i < num; ++i) {
        if (i == num - 1) {
            policy = policy + attributes->at(i);
        } else {
            policy = policy + attributes->at(i) + "&";
        }
    }

    unsigned char *message = (unsigned char*)malloc(9);
    message[0] = 'L';
    message[1] = 'a';
    message[2] = 'n';
    message[3] = 's';
    message[4] = 'e';
    message[5] = 'o';
    message[6] = 'n';
    message[7] = '!';
    message[8] = '\0';

    element_t sample_element;
    element_init_Zr(sample_element, pairing);
    policy_resolution pr;
    policy_generation pg;

    // get M and rho
    vector<string>* postfix_expression = pr.infixToPostfix(policy);
    binary_tree* binary_tree_expression = pr.postfixToBinaryTree(postfix_expression, sample_element);
    pg.generatePolicyInMatrixForm(binary_tree_expression);
    element_t_matrix* M = pg.getPolicyInMatrixFormFromTree(binary_tree_expression);
    map<signed long int, string>* rho = pg.getRhoFromTree(binary_tree_expression);

    access_structure *as = new access_structure(M, rho);

    BCET bcet;

    // set up
    vector<Key*> *psk = bcet.setUp();

    // key gen
    SecretKey *user_sk = bcet.keyGen(psk->at(1), psk->at(0), attributes);

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        bcet.encrypt(psk->at(1), as, message, psk->at(4), psk->at(3));
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", Encrypt: " << execution_time << "ms" << endl;
}

void BCET_test::trapdoor_test(signed long int num) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    vector<string> *attributes = new vector<string>();
    char n[4];
    for (signed long int i = 100; i <= 100 + num; ++i) {
        sprintf(n, "%ld", i);
        attributes->push_back(n);
    }

    BCET bcet;

    // set up
    vector<Key*> *psk = bcet.setUp();

    // key gen
    SecretKey *user_sk = bcet.keyGen(psk->at(1), psk->at(0), attributes);

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        bcet.trapdoor(user_sk);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", Trapdoor: " << execution_time << "ms" << endl;
}

void BCET_test::test_test(signed long int num) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    vector<string> *attributes = new vector<string>();
    char n[4];
    for (signed long int i = 100; i <= 100 + num; ++i) {
        sprintf(n, "%ld", i);
        attributes->push_back(n);
    }

    string policy = "";
    for (signed long int i = 0; i < num; ++i) {
        if (i == num - 1) {
            policy = policy + attributes->at(i);
        } else {
            policy = policy + attributes->at(i) + "&";
        }
    }

    unsigned char *message1 = (unsigned char*)malloc(9);
    message1[0] = 'L';
    message1[1] = 'a';
    message1[2] = 'n';
    message1[3] = 's';
    message1[4] = 'e';
    message1[5] = 'o';
    message1[6] = 'n';
    message1[7] = '!';
    message1[8] = '\0';
    unsigned char *message2 = (unsigned char*)malloc(9);
    message2[0] = 'L';
    message2[1] = 'a';
    message2[2] = 'n';
    message2[3] = 's';
    message2[4] = 'e';
    message2[5] = 'o';
    message2[6] = 'n';
    message2[7] = '!';
    message2[8] = '\0';

    element_t sample_element;
    element_init_Zr(sample_element, pairing);
    policy_resolution pr;
    policy_generation pg;

    // get M1 and rho1
    vector<string>* postfix_expression1 = pr.infixToPostfix(policy);
    binary_tree* binary_tree_expression1 = pr.postfixToBinaryTree(postfix_expression1, sample_element);
    pg.generatePolicyInMatrixForm(binary_tree_expression1);
    element_t_matrix* M1 = pg.getPolicyInMatrixFormFromTree(binary_tree_expression1);
    map<signed long int, string>* rho1 = pg.getRhoFromTree(binary_tree_expression1);

    // get M2 and rho2
    vector<string>* postfix_expression2 = pr.infixToPostfix(policy);
    binary_tree* binary_tree_expression2 = pr.postfixToBinaryTree(postfix_expression2, sample_element);
    pg.generatePolicyInMatrixForm(binary_tree_expression2);
    element_t_matrix* M2 = pg.getPolicyInMatrixFormFromTree(binary_tree_expression2);
    map<signed long int, string>* rho2 = pg.getRhoFromTree(binary_tree_expression2);

    access_structure *as1 = new access_structure(M1, rho1);
    access_structure *as2 = new access_structure(M2, rho2);

    BCET bcet;

    // set up
    vector<Key*> *psk = bcet.setUp();

    // key gen
    SecretKey *user1_sk = bcet.keyGen(psk->at(1), psk->at(0), attributes);
    SecretKey *user2_sk = bcet.keyGen(psk->at(1), psk->at(0), attributes);

    // encrypt
    Ciphertext_CET* ciphertext1 = bcet.encrypt((*psk)[1], as1, message1, psk->at(4), psk->at(3));
    Ciphertext_CET* ciphertext2 = bcet.encrypt(psk->at(1), as2, message2, psk->at(4), psk->at(3));

    // trapdoor
    SecretKey *tds1 = bcet.trapdoor(user1_sk);
    SecretKey *tds2 = bcet.trapdoor(user2_sk);

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        bcet.test(psk->at(1), ciphertext1, tds1, ciphertext2, tds2, psk->at(4), psk->at(3));
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", Test: " << execution_time << "ms" << endl;
}

void BCET_test::decrypt_test(signed long int num) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    vector<string> *attributes = new vector<string>();
    char n[4];
    for (signed long int i = 100; i <= 100 + num; ++i) {
        sprintf(n, "%ld", i);
        attributes->push_back(n);
    }

    string policy = "";
    for (signed long int i = 0; i < num; ++i) {
        if (i == num - 1) {
            policy = policy + attributes->at(i);
        } else {
            policy = policy + attributes->at(i) + "&";
        }
    }

    unsigned char *message = (unsigned char*)malloc(9);
    message[0] = 'L';
    message[1] = 'a';
    message[2] = 'n';
    message[3] = 's';
    message[4] = 'e';
    message[5] = 'o';
    message[6] = 'n';
    message[7] = '!';
    message[8] = '\0';

    element_t sample_element;
    element_init_Zr(sample_element, pairing);
    policy_resolution pr;
    policy_generation pg;

    // get M and rho
    vector<string>* postfix_expression = pr.infixToPostfix(policy);
    binary_tree* binary_tree_expression = pr.postfixToBinaryTree(postfix_expression, sample_element);
    pg.generatePolicyInMatrixForm(binary_tree_expression);
    element_t_matrix* M = pg.getPolicyInMatrixFormFromTree(binary_tree_expression);
    map<signed long int, string>* rho = pg.getRhoFromTree(binary_tree_expression);

    access_structure *as = new access_structure(M, rho);

    BCET bcet;

    // set up
    vector<Key*> *psk = bcet.setUp();

    // key gen
    SecretKey *user_sk = bcet.keyGen(psk->at(1), psk->at(0), attributes);

    // encrypt
    Ciphertext_CET* ciphertext = bcet.encrypt((*psk)[1], as, message, psk->at(4), psk->at(3));

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        bcet.decrypt(psk->at(1), ciphertext, user_sk);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", Decrypt: " << execution_time << "ms" << endl;
}