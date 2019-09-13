//
// Created by alan on 19-9-14.
//

#include "OCET_test.h"

OCET_test::OCET_test() {
    // init pairing
    pbc_param_t par;
    curve_param curves;
    pbc_param_init_set_str(par, curves.a_param.c_str());
    pairing_init_pbc_param(pairing, par);
}

void OCET_test::setup_test(signed long int num) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        OCET *ocet = new OCET();
        ocet->setUp();
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", Setup: " << execution_time << "ms" << endl;
}

void OCET_test::keygen_test(signed long int num) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    vector<string> *attributes = new vector<string>();
    char n[4];
    for (signed long int i = 100; i <= 100 + num; ++i) {
        sprintf(n, "%ld", i);
        attributes->push_back(n);
    }

    OCET ocet;

    // set up
    vector<Key*> *psk = ocet.setUp();

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        ocet.keyGen(psk->at(1), psk->at(0), attributes);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", KeyGen: " << execution_time << "ms" << endl;
}

void OCET_test::encrypt_test(signed long int num) {
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

    OCET ocet;

    // set up
    vector<Key*> *psk = ocet.setUp();

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        ocet.encrypt(psk->at(1), as, message, psk->at(4), psk->at(3));
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", Encrypt: " << execution_time << "ms" << endl;
}

void OCET_test::trapdoor_test(signed long int num) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    vector<string> *attributes = new vector<string>();
    char n[4];
    for (signed long int i = 100; i <= 100 + num; ++i) {
        sprintf(n, "%ld", i);
        attributes->push_back(n);
    }

    OCET ocet;

    // set up
    vector<Key*> *psk = ocet.setUp();

    // key gen
    vector<SecretKey*>  *user_sk = ocet.keyGen(psk->at(1), psk->at(0), attributes);

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        ocet.trapdoor(user_sk);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", Trapdoor: " << execution_time << "ms" << endl;
}

void OCET_test::transform1_test(signed long int num) {
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

    OCET ocet;

    // set up
    vector<Key*> *psk = ocet.setUp();

    // encrypt
    Ciphertext_CET* ciphertext = ocet.encrypt(psk->at(1), as, message, psk->at(4), psk->at(3));

    // key gen
    vector<SecretKey*> *user_sk = ocet.keyGen(psk->at(1), psk->at(0), attributes);

    // trapdoor
    vector<SecretKey*> *tds = ocet.trapdoor(user_sk);

    string *type1 = new string();
    *type1 = "Td";
    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        ocet.transform(psk->at(1), tds->at(0), type1, ciphertext, psk->at(4), psk->at(3));
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", Transform1: " << execution_time << "ms" << endl;
}

void OCET_test::transform2_test(signed long int num) {
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

    OCET ocet;

    // set up
    vector<Key*> *psk = ocet.setUp();

    // encrypt
    Ciphertext_CET* ciphertext = ocet.encrypt(psk->at(1), as, message, psk->at(4), psk->at(3));

    // key gen
    vector<SecretKey*> *user_sk = ocet.keyGen(psk->at(1), psk->at(0), attributes);

    string *type2 = new string();
    *type2 = "TK";
    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        ocet.transform(psk->at(1), user_sk->at(0), type2, ciphertext, psk->at(4), psk->at(3));
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", Transform2: " << execution_time << "ms" << endl;
}

void OCET_test::test_test(signed long int num) {
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

    OCET ocet;

    // set up
    vector<Key*> *psk = ocet.setUp();

    // key gen
    vector<SecretKey*> *user1_sk = ocet.keyGen(psk->at(1), psk->at(0), attributes);
    vector<SecretKey*> *user2_sk = ocet.keyGen(psk->at(1), psk->at(0), attributes);

    // encrypt
    Ciphertext_CET* ciphertext1 = ocet.encrypt((*psk)[1], as1, message1, psk->at(4), psk->at(3));
    Ciphertext_CET* ciphertext2 = ocet.encrypt(psk->at(1), as2, message2, psk->at(4), psk->at(3));

    // trapdoor
    vector<SecretKey*> *tds1 = ocet.trapdoor(user1_sk);
    vector<SecretKey*> *tds2 = ocet.trapdoor(user2_sk);

    // transform
    string *type1 = new string();
    *type1 = "Td";
    Ciphertext_CET* IT1_test = ocet.transform(psk->at(1), tds1->at(0), type1, ciphertext1, psk->at(4), psk->at(3));
    Ciphertext_CET* IT2_test = ocet.transform(psk->at(1), tds2->at(0), type1, ciphertext2, psk->at(4), psk->at(3));

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        ocet.test(psk->at(1), IT1_test, tds1, IT2_test, tds2);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", Test: " << execution_time << "ms" << endl;
}

void OCET_test::decrypt_test(signed long int num) {
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

    OCET ocet;

    // set up
    vector<Key*> *psk = ocet.setUp();

    // encrypt
    Ciphertext_CET* ciphertext = ocet.encrypt(psk->at(1), as, message, psk->at(4), psk->at(3));

    // key gen
    vector<SecretKey*> *user_sk = ocet.keyGen(psk->at(1), psk->at(0), attributes);

    // trapdoor
    vector<SecretKey*> *tds = ocet.trapdoor(user_sk);

    // transform
    string *type2 = new string();
    *type2 = "TK";
    Ciphertext_CET* IT = ocet.transform(psk->at(1), user_sk->at(0), type2, ciphertext, psk->at(4), psk->at(3));

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        ocet.decrypt(IT, user_sk->at(1));
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", Decrypt: " << execution_time << "ms" << endl;
}