//
// Created by alan on 19-9-14.
//

#include "HABE_test.h"

HABE_test::HABE_test() {
    // init pairing
    pbc_param_t par;
    curve_param curves;
    pbc_param_init_set_str(par, curves.a_param.c_str());
    pairing_init_pbc_param(pairing, par);
}

void HABE_test::setup_test(signed long int num) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        HABE *habe = new HABE();
        habe->setUp(num);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", Setup: " << execution_time << "ms" << endl;
}

void HABE_test::authkeygen_test(signed long int num) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    element_t g1_sample, g2_sample, gt_sample, zr_sample;
    element_init_G1(g1_sample, pairing);
    element_init_G2(g2_sample, pairing);
    element_init_GT(gt_sample, pairing);
    element_init_Zr(zr_sample, pairing);

    // host kgc
    element_t_vector *host_kgc_ID = new element_t_vector(num, zr_sample);
    for (signed long int i = 0; i < host_kgc_ID->length(); ++i) {
        element_random(host_kgc_ID->getElement(i));
    }
    string *host_kgc_name = new string();
    *host_kgc_name = "host_kgc";

    HABE habe;

    // Setup
    vector<Key*> *psk = habe.setUp(11);

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        habe.authKeyGen(psk->at(1), psk->at(0), host_kgc_ID);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", AuthKeyGen: " << execution_time << "ms" << endl;
}

void HABE_test::authdelegate_test(signed long int num) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    element_t g1_sample, g2_sample, gt_sample, zr_sample;
    element_init_G1(g1_sample, pairing);
    element_init_G2(g2_sample, pairing);
    element_init_GT(gt_sample, pairing);
    element_init_Zr(zr_sample, pairing);

    // host kgc
    element_t_vector *host_kgc_ID = new element_t_vector(num, zr_sample);
    for (signed long int i = 0; i < host_kgc_ID->length(); ++i) {
        element_random(host_kgc_ID->getElement(i));
    }
    string *host_kgc_name = new string();
    *host_kgc_name = "host_kgc";

    // kgc1
    element_t_vector *kgc1_ID = new element_t_vector(num + 1, zr_sample);
    for (signed long int i = 0; i < host_kgc_ID->length(); ++i) {
        element_set(kgc1_ID->getElement(i), host_kgc_ID->getElement(i));
    }
    element_random(kgc1_ID->getElement(kgc1_ID->length() - 1));
    string *kgc1_name = new string();
    *kgc1_name = "kgc1";

    HABE habe;

    // Setup
    vector<Key*> *psk = habe.setUp(11);

    // AuthKeyGen
    Key *SK_host_kgc = habe.authKeyGen(psk->at(1), psk->at(0), host_kgc_ID);

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        habe.authDelegate(psk->at(1), SK_host_kgc, kgc1_ID);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", AuthDelegate: " << execution_time << "ms" << endl;
}

void HABE_test::userkeygen_test(signed long int size_ID, signed long int num_attr) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    element_t g1_sample, g2_sample, gt_sample, zr_sample;
    element_init_G1(g1_sample, pairing);
    element_init_G2(g2_sample, pairing);
    element_init_GT(gt_sample, pairing);
    element_init_Zr(zr_sample, pairing);

    // host kgc
    element_t_vector *host_kgc_ID = new element_t_vector(size_ID, zr_sample);
    for (signed long int i = 0; i < host_kgc_ID->length(); ++i) {
        element_random(host_kgc_ID->getElement(i));
    }
    string *host_kgc_name = new string();
    *host_kgc_name = "host_kgc";

    vector<string> *attributes = new vector<string>();
    char n[4];
    for (signed long int i = 100; i <= 100 + num_attr; ++i) {
        sprintf(n, "%ld", i);
        attributes->push_back(n);
    }

    HABE habe;

    // Setup
    vector<Key*> *psk = habe.setUp(11);

    // AuthKeyGen
    Key *SK_host_kgc = habe.authKeyGen(psk->at(1), psk->at(0), host_kgc_ID);

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        habe.userKeyGen(psk->at(1), SK_host_kgc, host_kgc_ID, host_kgc_name, attributes);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << "(" << size_ID << "," << num_attr << ")" << ", UserKeyGen: " << execution_time << "ms" << endl;
}

void HABE_test::decrypt_test(signed long int size_ID, signed long int num_attr) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    element_t g1_sample, g2_sample, gt_sample, zr_sample;
    element_init_G1(g1_sample, pairing);
    element_init_G2(g2_sample, pairing);
    element_init_GT(gt_sample, pairing);
    element_init_Zr(zr_sample, pairing);

    // host kgc
    element_t_vector *host_kgc_ID = new element_t_vector(size_ID, zr_sample);
    for (signed long int i = 0; i < host_kgc_ID->length(); ++i) {
        element_random(host_kgc_ID->getElement(i));
    }
    string *host_kgc_name = new string();
    *host_kgc_name = "host_kgc";

    vector<string> *attributes = new vector<string>();
    char n[4];
    for (signed long int i = 100; i <= 100 + num_attr; ++i) {
        sprintf(n, "%ld", i);
        attributes->push_back(n);
    }

    string policy = "";
    for (signed long int i = 0; i < num_attr; ++i) {
        if (i == num_attr - 1) {
            policy = policy + attributes->at(i);
        } else {
            policy = policy + attributes->at(i) + "&";
        }
    }

    element_t m;
    element_init_GT(m, pairing);
    element_random(m);

    // get M and rho
    element_t sample_element;
    element_init_Zr(sample_element, pairing);
    policy_resolution pr;
    policy_generation pg;
    map<string, access_structure*> *AA = new map<string, access_structure*>();
    vector<string>* postfix_expression = pr.infixToPostfix(policy);
    binary_tree* binary_tree_expression = pr.postfixToBinaryTree(postfix_expression, sample_element);
    pg.generatePolicyInMatrixForm(binary_tree_expression);
    element_t_matrix* M = pg.getPolicyInMatrixFormFromTree(binary_tree_expression);
    map<signed long int, string>* rho = pg.getRhoFromTree(binary_tree_expression);
    access_structure *as = new access_structure(host_kgc_ID, M, rho, host_kgc_name);
    AA->insert(pair<string, access_structure*>(*host_kgc_name, as));

    HABE habe;

    // Setup
    vector<Key*> *psk = habe.setUp(11);

    // AuthKeyGen
    Key *SK_host_kgc = habe.authKeyGen(psk->at(1), psk->at(0), host_kgc_ID);

    // UserKeyGen
    SecretKey *SK_user = habe.userKeyGen(psk->at(1), SK_host_kgc, host_kgc_ID, host_kgc_name, attributes);

    // Encrypt
    Ciphertext_HCET *ciphertext = habe.encrypt(psk->at(1), AA, m);

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        habe.decrypt(ciphertext, SK_user);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << "(" << size_ID << "," << num_attr << ")" << ", Decrypt: " << execution_time << "ms" << endl;
}