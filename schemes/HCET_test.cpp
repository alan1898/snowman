//
// Created by alan on 19-9-14.
//

#include "HCET_test.h"

HCET_test::HCET_test() {
    // init pairing
    pbc_param_t par;
    curve_param curves;
    pbc_param_init_set_str(par, curves.a_param.c_str());
    pairing_init_pbc_param(pairing, par);
}

void HCET_test::setup_test(signed long int num) {
    clock_t start, end;
    double execution_time;
    double sum_time_20 = 0;

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        HCET *hcet = new HCET();
        hcet->setUp(num);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", Setup: " << execution_time << "ms" << endl;
}

void HCET_test::authkeygen_test(signed long int num) {
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

    HCET hcet;

    // Setup
    vector<Key*> *psk = hcet.setUp(11);

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        hcet.authKeyGen(psk->at(1), psk->at(0), host_kgc_ID);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", AuthKeyGen: " << execution_time << "ms" << endl;
}

void HCET_test::authdelegate_test(signed long int num) {
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

    HCET hcet;

    // Setup
    vector<Key*> *psk = hcet.setUp(11);

    // AuthKeyGen
    Key *SK_host_kgc = hcet.authKeyGen(psk->at(1), psk->at(0), host_kgc_ID);

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        hcet.authDelegate(psk->at(1), SK_host_kgc, kgc1_ID);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num << ", AuthDelegate: " << execution_time << "ms" << endl;
}

void HCET_test::userkeygen_test(signed long int size_ID, signed long int num_attr) {
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

    HCET hcet;

    // Setup
    vector<Key*> *psk = hcet.setUp(11);

    // AuthKeyGen
    Key *SK_host_kgc = hcet.authKeyGen(psk->at(1), psk->at(0), host_kgc_ID);

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        hcet.userKeyGen(psk->at(1), SK_host_kgc, host_kgc_ID, host_kgc_name, attributes);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << "(" << size_ID << "," << num_attr << ")" << ", UserKeyGen: " << execution_time << "ms" << endl;
}

void HCET_test::trapdoor_test(signed long int num_attr) {
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
    for (signed long int i = 100; i <= 100 + num_attr; ++i) {
        sprintf(n, "%ld", i);
        attributes->push_back(n);
    }

    HCET hcet;

    // Setup
    vector<Key*> *psk = hcet.setUp(11);

    // AuthKeyGen
    Key *SK_host_kgc = hcet.authKeyGen(psk->at(1), psk->at(0), host_kgc_ID);

    // UserKeyGen
    SecretKey *SK_user = hcet.userKeyGen(psk->at(1), SK_host_kgc, host_kgc_ID, host_kgc_name, attributes);

    for (signed long int i = 0; i < 20; ++i) {
        start = clock();
        hcet.trapdoor(SK_user);
        end = clock();
        execution_time = (double)(end-start)/CLOCKS_PER_SEC * 1000;
        sum_time_20 += execution_time;
    }

    execution_time = sum_time_20 / 20;

    cout << num_attr << ", Trapdoor: " << execution_time << "ms" << endl;
}