//
// Created by alan on 19-9-23.
//

#include "ODETC_test.h"

ODETC_test::ODETC_test() {
    // init pairing
    pbc_param_t par;
    curve_param curves;
    pbc_param_init_set_str(par, curves.a_param.c_str());
    pairing_init_pbc_param(pairing, par);
}

void ODETC_test::setup_test(signed long int num) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    vector<string> *attributes = new vector<string>();
    char n[4];
    for (signed long int i = 100; i < 100 + num; ++i) {
        sprintf(n, "%ld", i);
        attributes->push_back(n);
    }

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        ODETC *odetc = new ODETC();
        odetc->setUp(attributes);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", Setup: " << execution_time << "ms" << endl;
}

void ODETC_test::keygen_test(signed long int num) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    vector<string> *attributes = new vector<string>();
    char n[4];
    for (signed long int i = 100; i < 100 + num; ++i) {
        sprintf(n, "%ld", i);
        attributes->push_back(n);
    }

    ODETC odetc;

    // set up
    vector<Key*> *psk = odetc.setUp(attributes);

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        odetc.keyGen(psk->at(1), psk->at(0), attributes);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", KeyGen: " << execution_time << "ms" << endl;
}

void ODETC_test::encrypt_test(signed long int num) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    vector<string> *attributes = new vector<string>();
    char n[4];
    for (signed long int i = 100; i < 100 + num; ++i) {
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

    ODETC odetc;

    // set up
    vector<Key*> *psk = odetc.setUp(attributes);

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        odetc.encrypt(psk->at(1), as, message);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", Encrypt: " << execution_time << "ms" << endl;
}

void ODETC_test::trapdoor_test(signed long int num) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    vector<string> *attributes = new vector<string>();
    char n[4];
    for (signed long int i = 100; i < 100 + num; ++i) {
        sprintf(n, "%ld", i);
        attributes->push_back(n);
    }

    ODETC odetc;

    // set up
    vector<Key*> *psk = odetc.setUp(attributes);

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        odetc.trapdoor(psk->at(1), psk->at(0), attributes);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", Trapdoor: " << execution_time << "ms" << endl;
}

void ODETC_test::transform1_test(signed long int num) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    string *type1 = new string();
    *type1 = "td";
    string *type2 = new string();
    *type2 = "tk";

    vector<string> *attributes = new vector<string>();
    char n[4];
    for (signed long int i = 100; i < 100 + num; ++i) {
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

    ODETC odetc;

    // set up
    vector<Key*> *psk = odetc.setUp(attributes);

    // encrypt
    Ciphertext_CET *CT = odetc.encrypt(psk->at(1), as, message);

    // trapdoor
    SecretKey *Td = odetc.trapdoor(psk->at(1), psk->at(0), attributes);

    // transform1 test
    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        odetc.transform(CT, Td, type1);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", Transform1: " << execution_time << "ms" << endl;
}

void ODETC_test::transform2_test(signed long int num) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    string *type1 = new string();
    *type1 = "td";
    string *type2 = new string();
    *type2 = "tk";

    vector<string> *attributes = new vector<string>();
    char n[4];
    for (signed long int i = 100; i < 100 + num; ++i) {
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

    ODETC odetc;

    // set up
    vector<Key*> *psk = odetc.setUp(attributes);

    // encrypt
    Ciphertext_CET *CT = odetc.encrypt(psk->at(1), as, message);

    // key gen
    SecretKey *SK = odetc.keyGen(psk->at(1), psk->at(0), attributes);

    // transform2 test
    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        odetc.transform(CT, SK, type2);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", Transform2: " << execution_time << "ms" << endl;
}

void ODETC_test::decrypt_test(signed long int num) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    string *type1 = new string();
    *type1 = "td";
    string *type2 = new string();
    *type2 = "tk";

    vector<string> *attributes = new vector<string>();
    char n[4];
    for (signed long int i = 100; i < 100 + num; ++i) {
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

    ODETC odetc;

    // set up
    vector<Key*> *psk = odetc.setUp(attributes);

    // encrypt
    Ciphertext_CET *CT = odetc.encrypt(psk->at(1), as, message);

    // key gen
    SecretKey *SK = odetc.keyGen(psk->at(1), psk->at(0), attributes);

    // transform2
    Ciphertext_CET *IT_decrypt = odetc.transform(CT, SK, type2);

    // decrypt test
    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        odetc.decrypt(psk->at(1), IT_decrypt, SK);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", decrypt: " << execution_time << "ms" << endl;
}

void ODETC_test::test_test(signed long int num) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    string *type1 = new string();
    *type1 = "td";
    string *type2 = new string();
    *type2 = "tk";

    vector<string> *attributes = new vector<string>();
    char n[4];
    for (signed long int i = 100; i < 100 + num; ++i) {
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

    // get M and rho
    vector<string>* postfix_expression = pr.infixToPostfix(policy);
    binary_tree* binary_tree_expression = pr.postfixToBinaryTree(postfix_expression, sample_element);
    pg.generatePolicyInMatrixForm(binary_tree_expression);
    element_t_matrix* M = pg.getPolicyInMatrixFormFromTree(binary_tree_expression);
    map<signed long int, string>* rho = pg.getRhoFromTree(binary_tree_expression);

    access_structure *as = new access_structure(M, rho);

    ODETC odetc;

    // set up
    vector<Key*> *psk = odetc.setUp(attributes);

    // encrypt
    Ciphertext_CET *CT1 = odetc.encrypt(psk->at(1), as, message1);
    Ciphertext_CET *CT2 = odetc.encrypt(psk->at(1), as, message2);

    // trapdoor
    SecretKey *Td1 = odetc.trapdoor(psk->at(1), psk->at(0), attributes);
    SecretKey *Td2 = odetc.trapdoor(psk->at(1), psk->at(0), attributes);

    // transform1
    Ciphertext_CET *IT1_test = odetc.transform(CT1, Td1, type1);
    Ciphertext_CET *IT2_test = odetc.transform(CT2, Td2, type1);

    // test test
    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        odetc.test(IT1_test, Td1, IT2_test, Td2);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", Test: " << execution_time << "ms" << endl;
}