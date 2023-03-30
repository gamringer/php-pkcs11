/*
   +----------------------------------------------------------------------+
   | PHP Version 7                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) The PHP Group                                          |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Author: Guillaume Amringer                                           |
   +----------------------------------------------------------------------+
*/

#ifndef PKCSINT_H
#define PKCSINT_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "zend_exceptions.h"
#include "zend_interfaces.h"
#include "ext/standard/info.h"
#include "php_pkcs11.h"

#include <stdbool.h>
#include <dlfcn.h>

/* For compatibility with older PHP versions */
#ifndef ZEND_PARSE_PARAMETERS_NONE
#define ZEND_PARSE_PARAMETERS_NONE() \
    ZEND_PARSE_PARAMETERS_START(0, 0) \
    ZEND_PARSE_PARAMETERS_END()
#endif

typedef struct _pkcs11_object {
    bool initialised;
    void *pkcs11module;
    CK_FUNCTION_LIST_PTR functionList;
    zend_object std;
} pkcs11_object;

typedef struct _pkcs11_session_object {
    pkcs11_object *pkcs11;
    CK_SESSION_HANDLE session;
    CK_SLOT_ID slotID;
    zend_object std;
} pkcs11_session_object;

typedef struct _pkcs11_object_object {
    pkcs11_session_object *session;
    CK_OBJECT_HANDLE object;
    zend_object std;
} pkcs11_object_object;

typedef struct _pkcs11_key_object {
    pkcs11_session_object *session;
    CK_OBJECT_HANDLE key;
    zend_object std;
} pkcs11_key_object;

typedef struct _pkcs11_keypair_object {
    pkcs11_key_object *pkey;
    pkcs11_key_object *skey;
    zend_object std;
} pkcs11_keypair_object;

enum knownParamTypes {
    None,
    AwsGcmParams,
    GcmParams,
    RsaOaepParams,
    RsaPssParams,
    Ecdh1DeriveParams
};

typedef struct _pkcs11_mechanism_object {
    CK_MECHANISM mechanism;
    void *paramsObj;
    enum knownParamTypes paramsObjType;
    zend_object std;
} pkcs11_mechanism_object;

typedef struct _pkcs11_rsapssparams_object {
    CK_RSA_PKCS_PSS_PARAMS params;
    zend_object std;
} pkcs11_rsapssparams_object;

typedef struct _pkcs11_rsaoaepparams_object {
    CK_RSA_PKCS_OAEP_PARAMS params;
    zend_object std;
} pkcs11_rsaoaepparams_object;

typedef struct _pkcs11_awsgcmparams_object {
    CK_AWS_GCM_PARAMS params;
    zend_object std;
} pkcs11_awsgcmparams_object;

typedef struct _pkcs11_gcmparams_object {
    CK_GCM_PARAMS params;
    zend_object std;
} pkcs11_gcmparams_object;

typedef struct _pkcs11_chacha20params_object {
    CK_CHACHA20_PARAMS params;
    zend_object std;
} pkcs11_chacha20params_object;

typedef struct _pkcs11_salsa20params_object {
    CK_SALSA20_PARAMS params;
    zend_object std;
} pkcs11_salsa20params_object;

typedef struct _pkcs11_salsa20chacha20poly1305params_object {
    CK_SALSA20_CHACHA20_POLY1305_PARAMS params;
    zend_object std;
} pkcs11_salsa20chacha20poly1305params_object;

typedef struct _pkcs11_ecdh1deriveparams_object {
    CK_ECDH1_DERIVE_PARAMS params;
    zend_object std;
} pkcs11_ecdh1deriveparams_object;

typedef struct _pkcs11_signaturecontext_object {
    pkcs11_key_object *key;
    zend_object std;
} pkcs11_signaturecontext_object;

typedef struct _pkcs11_verificationcontext_object {
    pkcs11_key_object *key;
    zend_object std;
} pkcs11_verificationcontext_object;

typedef struct _pkcs11_digestcontext_object {
    pkcs11_session_object *session;
    zend_object std;
} pkcs11_digestcontext_object;

typedef struct _pkcs11_encryptioncontext_object {
    pkcs11_key_object *key;
    zend_object std;
} pkcs11_encryptioncontext_object;

typedef struct _pkcs11_decryptioncontext_object {
    pkcs11_key_object *key;
    zend_object std;
} pkcs11_decryptioncontext_object;


#define Z_PKCS11_P(zv)                               pkcs11_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_SESSION_P(zv)                       pkcs11_session_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_OBJECT_P(zv)                        pkcs11_object_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_KEY_P(zv)                           pkcs11_key_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_KEYPAIR_P(zv)                       pkcs11_keypair_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_MECHANISM_P(zv)                     pkcs11_mechanism_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_RSAPSSPARAMS_P(zv)                  pkcs11_rsapssparams_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_RSAOAEPPARAMS_P(zv)                 pkcs11_rsaoaepparams_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_AWSGCMPARAMS_P(zv)                  pkcs11_awsgcmparams_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_GCMPARAMS_P(zv)                     pkcs11_gcmparams_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_CHACHA20PARAMS_P(zv)                pkcs11_chacha20params_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_SALSA20PARAMS_P(zv)                 pkcs11_salsa20params_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_SALSA20CHACHA20POLY1305PARAMS_P(zv) pkcs11_salsa20chacha20poly1305params_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_ECDH1DERIVEPARAMS_P(zv)             pkcs11_ecdh1deriveparams_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_SIGNATURECONTEXT_P(zv)              pkcs11_signaturecontext_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_VERIFICATIONCONTEXT_P(zv)           pkcs11_verificationcontext_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_DIGESTCONTEXT_P(zv)                 pkcs11_digestcontext_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_ENCRYPTIONCONTEXT_P(zv)             pkcs11_encryptioncontext_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_DECRYPTIONCONTEXT_P(zv)             pkcs11_decryptioncontext_from_zend_object(Z_OBJ_P((zv)))

#define DECLARE_MAGIC_FUNCS(tt, classname)                                  \
static inline tt##_object *tt##_from_zend_object(zend_object *obj) {        \
    return (tt##_object *) ((char *) (obj) - XtOffsetOf(tt##_object, std)); \
}                                                                           \
extern void register_##tt();                                                \
extern zend_class_entry *ce_Pkcs11_##classname;

DECLARE_MAGIC_FUNCS(pkcs11,                               Module)
DECLARE_MAGIC_FUNCS(pkcs11_session,                       Session)
DECLARE_MAGIC_FUNCS(pkcs11_object,                        P11Object)
DECLARE_MAGIC_FUNCS(pkcs11_key,                           Key)
DECLARE_MAGIC_FUNCS(pkcs11_keypair,                       KeyPair)
DECLARE_MAGIC_FUNCS(pkcs11_mechanism,                     Mechanism)
DECLARE_MAGIC_FUNCS(pkcs11_rsapssparams,                  RsaPssParams)
DECLARE_MAGIC_FUNCS(pkcs11_rsaoaepparams,                 RsaOaepParams)
DECLARE_MAGIC_FUNCS(pkcs11_awsgcmparams,                  AwsGcmParams)
DECLARE_MAGIC_FUNCS(pkcs11_gcmparams,                     GcmParams)
DECLARE_MAGIC_FUNCS(pkcs11_chacha20params,                ChaCha20Params)
DECLARE_MAGIC_FUNCS(pkcs11_salsa20params,                 Salsa20Params)
DECLARE_MAGIC_FUNCS(pkcs11_salsa20chacha20poly1305params, Salsa20Chacha20Poly1305Params)
DECLARE_MAGIC_FUNCS(pkcs11_ecdh1deriveparams,             Ecdh1DeriveParams)
DECLARE_MAGIC_FUNCS(pkcs11_signaturecontext,              SignatureContext)
DECLARE_MAGIC_FUNCS(pkcs11_verificationcontext,           VerificationContext)
DECLARE_MAGIC_FUNCS(pkcs11_digestcontext,                 DigestContext)
DECLARE_MAGIC_FUNCS(pkcs11_encryptioncontext,             EncryptionContext)
DECLARE_MAGIC_FUNCS(pkcs11_decryptioncontext,             DecryptionContext)

#if PHP_VERSION_ID < 80100

#define PKCS11_ACC_NOT_SERIALIZABLE(ce) \
    ce->serialize = zend_class_serialize_deny; \
    ce->unserialize = zend_class_unserialize_deny;

#else

#define PKCS11_ACC_NOT_SERIALIZABLE(ce) \
    ce->ce_flags |= ZEND_ACC_NOT_SERIALIZABLE;

#endif

#define DEFINE_MAGIC_FUNCS(tt, lowername, classname)                            \
static zend_object *tt##_ctor(zend_class_entry *ce) {                           \
    tt##_object *objval = zend_object_alloc(sizeof(tt##_object), ce);           \
                                                                                \
    zend_object_std_init(&objval->std, ce);                                     \
    object_properties_init(&objval->std, ce);                                   \
    objval->std.handlers = &tt##_handlers;                                      \
                                                                                \
    return &objval->std;                                                        \
}                                                                               \
static void tt##_dtor(zend_object *zobj) {                                      \
    tt##_object *objval = tt##_from_zend_object(zobj);                          \
    tt##_shutdown(objval);                                                      \
    zend_object_std_dtor(&objval->std);                                         \
}                                                                               \
void register_##tt() {                                                          \
    zend_class_entry ce;                                                        \
    memcpy(&tt##_handlers, &std_object_handlers, sizeof(zend_object_handlers)); \
    INIT_NS_CLASS_ENTRY(ce, "Pkcs11", #classname, lowername##_class_functions); \
    ce.create_object = tt##_ctor;                                               \
    tt##_handlers.offset = XtOffsetOf(tt##_object, std);                        \
    tt##_handlers.clone_obj = NULL;                                             \
    tt##_handlers.free_obj = tt##_dtor;                                         \
    ce_Pkcs11_##classname = zend_register_internal_class(&ce);                  \
    PKCS11_ACC_NOT_SERIALIZABLE(ce_Pkcs11_##classname);                         \
}


extern void pkcs11_error(CK_RV rv, char *error);
extern void general_error(char *generic, char *specific);

extern void parseTemplate(HashTable **template, CK_ATTRIBUTE_PTR *templateObj, int *templateItemCount);
extern void freeTemplate(CK_ATTRIBUTE_PTR templateObj);
extern void getObjectClass(pkcs11_session_object *session, CK_OBJECT_HANDLE_PTR hObject, CK_ULONG_PTR classId);

extern CK_RV php_C_GenerateRandom(const pkcs11_session_object * const objval, zend_long php_RandomLen, zval *retval);
extern CK_RV php_C_SeedRandom(const pkcs11_session_object * const objval, zend_string *php_pSeed);
extern CK_RV php_C_GetSessionInfo(const pkcs11_session_object * const objval, zval *retval);
extern CK_RV php_C_GenerateKey(pkcs11_session_object *objval, zval *mechanism, HashTable *template, zval *retval);
extern CK_RV php_C_GenerateKeyPair(pkcs11_session_object *objval, zval *mechanism, HashTable *pkTemplate, HashTable *skTemplate, zval *retvalPk, zval *retvalSk);
extern CK_RV php_C_CreateObject(pkcs11_session_object *objval, HashTable *template, zval *retval);
extern CK_RV php_C_CopyObject(pkcs11_session_object *objval, zval *objectOrig, HashTable *template, zval *retval);
extern CK_RV php_C_DestroyObject(pkcs11_session_object *objval, zval *object);
extern CK_RV php_C_FindObjects(pkcs11_session_object *objval,  CK_ATTRIBUTE *tmpl, int nbAttributes, zval *return_value);

#endif
