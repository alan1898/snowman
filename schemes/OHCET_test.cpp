//
// Created by alan on 19-9-14.
//

#include "OHCET_test.h"

OHCET_test::OHCET_test() {
    // init pairing
    pbc_param_t par;
    curve_param curves;
    pbc_param_init_set_str(par, curves.a_param.c_str());
    pairing_init_pbc_param(pairing, par);
}

void OHCET_test::setup_test(signed long int num) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        OHCET *ohcet = new OHCET();
        ohcet->setUp(num);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", Setup: " << execution_time << "ms" << endl;
}

void OHCET_test::authkeygen_test(signed long int num) {
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

    OHCET ohcet;

    // Setup
    vector<Key*> *psk = ohcet.setUp(11);

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        ohcet.authKeyGen(psk->at(1), psk->at(0), host_kgc_ID);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", AuthKeyGen: " << execution_time << "ms" << endl;
}

void OHCET_test::authdelegate_test(signed long int num) {
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

    OHCET ohcet;

    // Setup
    vector<Key*> *psk = ohcet.setUp(11);

    // AuthKeyGen
    Key *SK_host_kgc = ohcet.authKeyGen(psk->at(1), psk->at(0), host_kgc_ID);

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        ohcet.authDelegate(psk->at(1), SK_host_kgc, kgc1_ID);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", AuthDelegate: " << execution_time << "ms" << endl;
}

void OHCET_test::userkeygen_test(signed long int size_ID, signed long int num_attr) {
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
    for (signed long int i = 100; i < 100 + num_attr; ++i) {
        sprintf(n, "%ld", i);
        attributes->push_back(n);
    }

    OHCET ohcet;

    // Setup
    vector<Key*> *psk = ohcet.setUp(11);

    // AuthKeyGen
    Key *SK_host_kgc = ohcet.authKeyGen(psk->at(1), psk->at(0), host_kgc_ID);

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        ohcet.userKeyGen(psk->at(1), SK_host_kgc, host_kgc_ID, host_kgc_name, attributes);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << "(" << size_ID << "," << num_attr << ")" << ", UserKeyGen: " << execution_time << "ms" << endl;
}

void OHCET_test::trapdoor_test(signed long int num_attr) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    element_t g1_sample, g2_sample, gt_sample, zr_sample;
    element_init_G1(g1_sample, pairing);
    element_init_G2(g2_sample, pairing);
    element_init_GT(gt_sample, pairing);
    element_init_Zr(zr_sample, pairing);

    // host kgc
    element_t_vector *host_kgc_ID = new element_t_vector(5, zr_sample);
    for (signed long int i = 0; i < host_kgc_ID->length(); ++i) {
        element_random(host_kgc_ID->getElement(i));
    }
    string *host_kgc_name = new string();
    *host_kgc_name = "host_kgc";

    vector<string> *attributes = new vector<string>();
    char n[4];
    for (signed long int i = 100; i < 100 + num_attr; ++i) {
        sprintf(n, "%ld", i);
        attributes->push_back(n);
    }

    OHCET ohcet;

    // Setup
    vector<Key*> *psk = ohcet.setUp(11);

    // AuthKeyGen
    Key *SK_host_kgc = ohcet.authKeyGen(psk->at(1), psk->at(0), host_kgc_ID);

    // UserKeyGen
    vector<SecretKey*> *SK_user = ohcet.userKeyGen(psk->at(1), SK_host_kgc, host_kgc_ID, host_kgc_name, attributes);

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        ohcet.trapdoor(SK_user);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num_attr << ", Trapdoor: " << execution_time << "ms" << endl;
}

void OHCET_test::encrypt_test(signed long int max_kgc, signed long int num_kgc, signed long int size_ID, signed long int num_attr) {
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

    vector<string> *attributes = new vector<string>();
    char n[4];
    for (signed long int i = 100; i < 100 + num_attr; ++i) {
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
    char name[4];
    for (signed long int i = 100; i < num_kgc + 100; ++i) {
        sprintf(name, "%ld", i);
        string *host_kgc_name = new string();
        *host_kgc_name = name;
        access_structure *as = new access_structure(host_kgc_ID, M, rho, host_kgc_name);
        AA->insert(pair<string, access_structure*>(*host_kgc_name, as));
    }

    OHCET ohcet;

    // Setup
    vector<Key*> *psk = ohcet.setUp(max_kgc);

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        ohcet.encrypt(psk->at(1), AA, message, psk->at(4), psk->at(3));
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << "(" << num_kgc << "," << size_ID << "," << num_attr << ")" << ", Encrypt: " << execution_time << "ms" << endl;
}

void OHCET_test::decrypt_test(signed long int max_kgc, signed long int num_kgc, signed long int size_ID,
                              signed long int num_attr) {
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

    vector<string> *attributes = new vector<string>();
    char n[4];
    for (signed long int i = 100; i < 100 + num_attr; ++i) {
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
    char name[4];
    for (signed long int i = 100; i < num_kgc + 100; ++i) {
        sprintf(name, "%ld", i);
        string *host_kgc_name = new string();
        *host_kgc_name = name;
        access_structure *as = new access_structure(host_kgc_ID, M, rho, host_kgc_name);
        AA->insert(pair<string, access_structure*>(*host_kgc_name, as));
    }

    OHCET ohcet;

    string *host_kgc_name = new string();
    *host_kgc_name = "100";

    // Setup
    vector<Key*> *psk = ohcet.setUp(max_kgc);

    // Encrypt
    Ciphertext_HCET *ciphertext = ohcet.encrypt(psk->at(1), AA, message, psk->at(4), psk->at(3));

    // AuthKeyGen
    Key *SK_host_kgc = ohcet.authKeyGen(psk->at(1), psk->at(0), host_kgc_ID);

    // UserKeyGen
    vector<SecretKey*> *SK_user = ohcet.userKeyGen(psk->at(1), SK_host_kgc, host_kgc_ID, host_kgc_name, attributes);

    // Transform
    string *type1 = new string();
    *type1 = "Td";
    string *type2 = new string();
    *type2 = "TK";
    Ciphertext_HCET *IT = ohcet.transform(psk->at(1), SK_user->at(0), type2, ciphertext, psk->at(4), psk->at(3));

    // Decrypt Test
    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        ohcet.decrypt(psk->at(1), IT, SK_user->at(1));
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    unsigned char* m_user = ohcet.decrypt(psk->at(1), IT, SK_user->at(1));
    printf("Decrypt: %s\n", m_user);

    cout << "(" << num_kgc << "," << size_ID << "," << num_attr << ")" << ", Decrypt: " << execution_time << "ms" << endl;
}

void OHCET_test::transform1_test(signed long int max_kgc, signed long int num_kgc, signed long int size_ID,
                                signed long int num_attr) {
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

    vector<string> *attributes = new vector<string>();
    char n[4];
    for (signed long int i = 100; i < 100 + num_attr; ++i) {
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
    char name[4];
    for (signed long int i = 100; i < num_kgc + 100; ++i) {
        sprintf(name, "%ld", i);
        string *host_kgc_name = new string();
        *host_kgc_name = name;
        access_structure *as = new access_structure(host_kgc_ID, M, rho, host_kgc_name);
        AA->insert(pair<string, access_structure*>(*host_kgc_name, as));
    }

    OHCET ohcet;

    string *host_kgc_name = new string();
    *host_kgc_name = "100";

    // Setup
    vector<Key*> *psk = ohcet.setUp(max_kgc);

    // Encrypt
    Ciphertext_HCET *ciphertext = ohcet.encrypt(psk->at(1), AA, message, psk->at(4), psk->at(3));

    // AuthKeyGen
    Key *SK_host_kgc = ohcet.authKeyGen(psk->at(1), psk->at(0), host_kgc_ID);

    // UserKeyGen
    vector<SecretKey*> *SK_user = ohcet.userKeyGen(psk->at(1), SK_host_kgc, host_kgc_ID, host_kgc_name, attributes);

    // Trapdoor
    vector<SecretKey*> *Td_user = ohcet.trapdoor(SK_user);

    // Transform 1 Test
    string *type1 = new string();
    *type1 = "Td";
    string *type2 = new string();
    *type2 = "TK";
    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        ohcet.transform(psk->at(1), Td_user->at(0), type1, ciphertext, psk->at(4), psk->at(3));
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << "(" << num_kgc << "," << size_ID << "," << num_attr << ")" << ", Transform1: " << execution_time << "ms" << endl;
}

void OHCET_test::transform2_test(signed long int max_kgc, signed long int num_kgc, signed long int size_ID,
                                 signed long int num_attr) {
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

    vector<string> *attributes = new vector<string>();
    char n[4];
    for (signed long int i = 100; i < 100 + num_attr; ++i) {
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
    char name[4];
    for (signed long int i = 100; i < num_kgc + 100; ++i) {
        sprintf(name, "%ld", i);
        string *host_kgc_name = new string();
        *host_kgc_name = name;
        access_structure *as = new access_structure(host_kgc_ID, M, rho, host_kgc_name);
        AA->insert(pair<string, access_structure*>(*host_kgc_name, as));
    }

    OHCET ohcet;

    string *host_kgc_name = new string();
    *host_kgc_name = "100";

    // Setup
    vector<Key*> *psk = ohcet.setUp(max_kgc);

    // Encrypt
    Ciphertext_HCET *ciphertext = ohcet.encrypt(psk->at(1), AA, message, psk->at(4), psk->at(3));

    // AuthKeyGen
    Key *SK_host_kgc = ohcet.authKeyGen(psk->at(1), psk->at(0), host_kgc_ID);

    // UserKeyGen
    vector<SecretKey*> *SK_user = ohcet.userKeyGen(psk->at(1), SK_host_kgc, host_kgc_ID, host_kgc_name, attributes);

    // Transform 2 Test
    string *type1 = new string();
    *type1 = "Td";
    string *type2 = new string();
    *type2 = "TK";
    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        ohcet.transform(psk->at(1), SK_user->at(0), type2, ciphertext, psk->at(4), psk->at(3));
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << "(" << num_kgc << "," << size_ID << "," << num_attr << ")" << ", Transform2: " << execution_time << "ms" << endl;
}

void OHCET_test::test_test(signed long int max_kgc, signed long int num_kgc, signed long int size_ID,
                           signed long int num_attr) {
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

    vector<string> *attributes = new vector<string>();
    char n[4];
    for (signed long int i = 100; i < 100 + num_attr; ++i) {
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
    char name[4];
    for (signed long int i = 100; i < num_kgc + 100; ++i) {
        sprintf(name, "%ld", i);
        string *host_kgc_name = new string();
        *host_kgc_name = name;
        access_structure *as = new access_structure(host_kgc_ID, M, rho, host_kgc_name);
        AA->insert(pair<string, access_structure*>(*host_kgc_name, as));
    }

    string *host_kgc_name = new string();
    *host_kgc_name = "100";

    OHCET ohcet;

    // Setup
    vector<Key*> *psk = ohcet.setUp(max_kgc);

    // Encrypt
    Ciphertext_HCET *ciphertext1 = ohcet.encrypt(psk->at(1), AA, message1, psk->at(4), psk->at(3));
    Ciphertext_HCET *ciphertext2 = ohcet.encrypt(psk->at(1), AA, message2, psk->at(4), psk->at(3));

    // AuthKeyGen
    Key *SK_host_kgc = ohcet.authKeyGen(psk->at(1), psk->at(0), host_kgc_ID);

    // UserKeyGen
    vector<SecretKey*> *SK_user1 = ohcet.userKeyGen(psk->at(1), SK_host_kgc, host_kgc_ID, host_kgc_name, attributes);
    vector<SecretKey*> *SK_user2 = ohcet.userKeyGen(psk->at(1), SK_host_kgc, host_kgc_ID, host_kgc_name, attributes);

    // Trapdoor
    vector<SecretKey*> *Td_user1 = ohcet.trapdoor(SK_user1);
    vector<SecretKey*> *Td_user2 = ohcet.trapdoor(SK_user2);

    // Transform
    string *type1 = new string();
    *type1 = "Td";
    string *type2 = new string();
    *type2 = "TK";
    Ciphertext_HCET *IT1_test = ohcet.transform(psk->at(1), Td_user1->at(0), type1, ciphertext1, psk->at(4), psk->at(3));
    Ciphertext_HCET *IT2_test = ohcet.transform(psk->at(1), Td_user2->at(0), type1, ciphertext2, psk->at(4), psk->at(3));

    // Test Test
    // Test Test
    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        ohcet.test(psk->at(1), IT1_test, Td_user1, IT2_test, Td_user2);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    bool *test_res = ohcet.test(psk->at(1), IT1_test, Td_user1, IT2_test, Td_user2);
    if (*test_res == true) {
        cout << "message1 and message2 are the same" << endl;
    } else {
        cout << "message1 and message2 are different" << endl;
    }

    cout << "(" << num_kgc << "," << size_ID << "," << num_attr << ")" << ", Test: " << execution_time << "ms" << endl;
}