#ifndef _SECP256K1_MODULE_MULTISET_MAIN_
#define _SECP256K1_MODULE_MULTISET_MAIN_

//����ο�����˵���вο����ϡ�4���д��е�ͷ�ļ�˼·
//����STD�в�������python�����ֳɵ���Բ�����������Ϊ�ײ�����
//����������ڵײ����㲿������secp256k1����Բ���������Լ�hash��������
//������ֱ�ŵ�����ͷ�ļ��зֱ���ã�����������python����Բ���߿���з�װ��
//ECMH��ʵ����Ҫ��ע������������Բ������multiset�Ľ����
/*include_HEADERS += include / secp256k1_multiset.h
noinst_HEADERS += src / modules / multiset / main_impl.h
noinst_HEADERS += src / modules / multiset / tests_impl.h
if USE_BENCHMARK
noinst_PROGRAMS += bench_multiset
bench_multiset_SOURCES = src / bench_multiset.c
bench_multiset_LDADD = libsecp256k1.la $(SECP_LIBS) $(COMMON_LIB)
endif
*/

#include "include/secp256k1_multiset.h"
#include "hash.h"
#include "field.h"
#include "group.h"

/* ��ȺԪ�أ��ſɱȾ���ת��Ϊ multiset.
 ����Ҳ�ο��ˡ�4���д��е�˼·������ʹ������ֵ��z = 0 */
static void multiset_from_gej_var(secp256k1_multiset *target, const secp256k1_gej *input) {

    if (input->infinity) {
        memset(&target->d, 0, sizeof(target->d));
    }
    else {
        secp256k1_fe_get_b32(target->d, &input->x);
        secp256k1_fe_get_b32(target->d+32, &input->y);
        secp256k1_fe_get_b32(target->d+64, &input->z);
    }
}

/*��multisetת��ΪȺԪ�أ��ſɱȾ���
 ����ʹ������ֵ��z = 0  */
static void gej_from_multiset_var(secp256k1_gej *target,  const secp256k1_multiset *input) {

    secp256k1_fe_set_b32(&target->x, input->d);
    secp256k1_fe_set_b32(&target->y, input->d+32);
    secp256k1_fe_set_b32(&target->z, input->d+64);

    target->infinity = secp256k1_fe_is_zero(&target->z) ? 1 : 0;
}

/*������Ԫ��ת��ΪȺԪ�أ����䣩
����ʹ�ÿ��ٵ��Ǻ㶨ʱ���trial-and-rehash
��Ȼ���ں㶨ʱ���㷨���ͺ�˵����������һ��
����Ӧ�ò�����UTXO Commitment�������ǲ����Ķ�ʱ����
��Ϊ����û����ͼ���صײ�����*/ 
static void ge_from_data_var(secp256k1_ge *target, const unsigned char *input, size_t inputLen) {

    secp256k1_sha256_t hasher;
    unsigned char hash[32];

    /* hash to a first trial */
    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, input, inputLen);
    secp256k1_sha256_finalize(&hasher, hash);

    /* loop through trials,ÿ��ѭ���ĳɹ���Ϊ50%*/
    for(;;)
    {
        secp256k1_fe x;

        if (secp256k1_fe_set_b32(&x, hash)) {

            if (secp256k1_ge_set_xquad(target, &x)) {

                VERIFY_CHECK(secp256k1_ge_is_valid_var(target));
                VERIFY_CHECK(!secp256k1_ge_is_infinity(target));
                break;
            }
        }

        /* �µ�һ��hash */
        secp256k1_sha256_initialize(&hasher);
        secp256k1_sha256_write(&hasher, hash, sizeof(hash));
        secp256k1_sha256_finalize(&hasher, hash);
    }

}


/* ��multiset�����Ԫ�� */
int secp256k1_multiset_add(const secp256k1_context* ctx,
                              secp256k1_multiset *multiset,
                              const unsigned char *input, size_t inputLen)
{
    secp256k1_ge newelm;
    secp256k1_gej source, target;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(multiset != NULL);
    ARG_CHECK(input != NULL);

    gej_from_multiset_var(&source, multiset);
    ge_from_data_var(&newelm, input, inputLen);

    secp256k1_gej_add_ge_var(&target, &source, &newelm, NULL);

    secp256k1_fe_normalize(&target.x);
    secp256k1_fe_normalize(&target.y);
    secp256k1_fe_normalize(&target.z);
    multiset_from_gej_var(multiset, &target);

    return 1;
}

/* ��multiset��ɾ��Ԫ�� */
int secp256k1_multiset_remove(const secp256k1_context* ctx,
                              secp256k1_multiset *multiset,
                              const unsigned char *input, size_t inputLen)
{
    secp256k1_ge newelm, neg_newelm;
    secp256k1_gej source, target;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(multiset != NULL);
    ARG_CHECK(input != NULL);

    gej_from_multiset_var(&source, multiset);
    ge_from_data_var(&newelm, input, inputLen);

    /* find inverse and add */
    secp256k1_ge_neg(&neg_newelm, &newelm);
    secp256k1_gej_add_ge_var(&target, &source, &neg_newelm, NULL);

    secp256k1_fe_normalize(&target.x);
    secp256k1_fe_normalize(&target.y);
    secp256k1_fe_normalize(&target.z);
    multiset_from_gej_var(multiset, &target);

    return 1;
}

/* ����multisetֱ����� */
int secp256k1_multiset_combine(const secp256k1_context* ctx, secp256k1_multiset *multiset, const secp256k1_multiset *input)
{
    secp256k1_gej gej_multiset, gej_input, gej_result;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(multiset != NULL);
    ARG_CHECK(input != NULL);

    gej_from_multiset_var(&gej_multiset, multiset);
    gej_from_multiset_var(&gej_input, input);

    secp256k1_gej_add_var(&gej_result, &gej_multiset, &gej_input, NULL);

    secp256k1_fe_normalize(&gej_result.x);
    secp256k1_fe_normalize(&gej_result.y);
    secp256k1_fe_normalize(&gej_result.z);
    multiset_from_gej_var(multiset, &gej_result);

    return 1;
}


/* ����multiset����hash�õ����յ�hash���*/
int secp256k1_multiset_finalize(const secp256k1_context* ctx, unsigned char *resultHash, const secp256k1_multiset *multiset)
{
    secp256k1_sha256_t hasher;
    unsigned char buffer[64];
    secp256k1_gej gej;
    secp256k1_ge ge;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(resultHash != NULL);
    ARG_CHECK(multiset != NULL);

    gej_from_multiset_var(&gej, multiset);
    if (gej.infinity) {

        memset(buffer, 0xff, sizeof(buffer));
    } else {
        /* ����Ӧ����������������֮���ٽ������� */
        secp256k1_ge_set_gej(&ge, &gej);
        secp256k1_fe_normalize(&ge.x);
        secp256k1_fe_normalize(&ge.y);
        secp256k1_fe_get_b32(buffer, &ge.x);
        secp256k1_fe_get_b32(buffer+32, &ge.y);
    }

    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, buffer, sizeof(buffer));
    secp256k1_sha256_finalize(&hasher, resultHash);

    return 1;
}

/* ��ʼ�����п����ݳ�����multiset����Jacobian GE infinite��ʾ */
int secp256k1_multiset_init(const secp256k1_context* ctx, secp256k1_multiset *multiset) {


    const secp256k1_gej inf = SECP256K1_GEJ_CONST_INFINITY;

    VERIFY_CHECK(ctx != NULL);

    multiset_from_gej_var(multiset, &inf);

    return 1;
}
#endif