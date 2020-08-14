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

#include "pkcs11int.h"

zend_class_entry *ce_Pkcs11_Key;
static zend_object_handlers pkcs11_key_handlers;


ZEND_BEGIN_ARG_INFO_EX(arginfo_initializeSignature, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, mechanismId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, mechanismArgument, IS_OBJECT, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_sign, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, mechanismId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, mechanismArgument, IS_OBJECT, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_verify, 0, 0, 3)
    ZEND_ARG_TYPE_INFO(0, mechanismId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, signature, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, mechanismArgument, IS_OBJECT, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_getAttributeValue, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, attributeIds, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_encrypt, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, mechanismId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, plaintext, IS_STRING, 0)
    ZEND_ARG_INFO(0, mechanismArgument)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_decrypt, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, mechanismId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, ciphertext, IS_STRING, 0)
    ZEND_ARG_INFO(0, mechanismArgument)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_wrap, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, mechanismId, IS_LONG, 0)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, mechanismArgument)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_unwrap, 0, 0, 3)
    ZEND_ARG_TYPE_INFO(0, mechanismId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, ciphertext, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, template, IS_ARRAY, 0)
    ZEND_ARG_INFO(0, mechanismArgument)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_derive, 0, 0, 3)
    ZEND_ARG_TYPE_INFO(0, mechanismId, IS_LONG, 0)
    ZEND_ARG_INFO(0, mechanismArgument)
    ZEND_ARG_TYPE_INFO(0, template, IS_ARRAY, 0)
ZEND_END_ARG_INFO()


PHP_METHOD(Key, initializeSignature) {

    CK_RV rv;
    zend_long mechanismId;
    zval *mechanismArgument = NULL;

    ZEND_PARSE_PARAMETERS_START(1,2)
        Z_PARAM_LONG(mechanismId)
        Z_PARAM_OPTIONAL
        Z_PARAM_ZVAL(mechanismArgument)
    ZEND_PARSE_PARAMETERS_END();

    CK_MECHANISM mechanism = {mechanismId, NULL_PTR, 0};

    if (mechanismArgument) {
        if(zend_string_equals_literal(Z_OBJ_P(mechanismArgument)->ce->name, "Pkcs11\\RsaPssParams")) {
            pkcs11_rsapssparams_object *mechanismObj = Z_PKCS11_RSAPSSPARAMS_P(mechanismArgument);
            mechanism.pParameter = &mechanismObj->params;
            mechanism.ulParameterLen = sizeof(mechanismObj->params);
        }
    }

    pkcs11_key_object *objval = Z_PKCS11_KEY_P(ZEND_THIS);
    rv = objval->session->pkcs11->functionList->C_SignInit(
        objval->session->session,
        &mechanism,
        objval->key
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to sign");
        return;
    }

    pkcs11_signaturecontext_object* context_obj;

    object_init_ex(return_value, ce_Pkcs11_SignatureContext);
    context_obj = Z_PKCS11_SIGNATURECONTEXT_P(return_value);
    context_obj->key = objval;
}


PHP_METHOD(Key, sign) {

    CK_RV rv;
    zend_long mechanismId;
    zend_string *data;
    zval *mechanismArgument = NULL;

    ZEND_PARSE_PARAMETERS_START(2,3)
        Z_PARAM_LONG(mechanismId)
        Z_PARAM_STR(data)
        Z_PARAM_OPTIONAL
        Z_PARAM_ZVAL(mechanismArgument)
    ZEND_PARSE_PARAMETERS_END();

    CK_MECHANISM mechanism = {mechanismId, NULL_PTR, 0};

    if (mechanismArgument) {
        if(zend_string_equals_literal(Z_OBJ_P(mechanismArgument)->ce->name, "Pkcs11\\RsaPssParams")) {
            pkcs11_rsapssparams_object *mechanismObj = Z_PKCS11_RSAPSSPARAMS_P(mechanismArgument);
            mechanism.pParameter = &mechanismObj->params;
            mechanism.ulParameterLen = sizeof(mechanismObj->params);
        }
    }

    pkcs11_key_object *objval = Z_PKCS11_KEY_P(ZEND_THIS);
    rv = objval->session->pkcs11->functionList->C_SignInit(
        objval->session->session,
        &mechanism,
        objval->key
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to sign");
        return;
    }

    CK_ULONG signatureLen;
    rv = objval->session->pkcs11->functionList->C_Sign(
        objval->session->session,
        ZSTR_VAL(data),
        ZSTR_LEN(data),
        NULL_PTR,
        &signatureLen
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to sign");
        return;
    }

    CK_BYTE_PTR signature = ecalloc(signatureLen, sizeof(CK_BYTE));
    rv = objval->session->pkcs11->functionList->C_Sign(
        objval->session->session,
        ZSTR_VAL(data),
        ZSTR_LEN(data),
        signature,
        &signatureLen
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to sign");
        return;
    }

    zend_string *returnval;
    returnval = zend_string_alloc(signatureLen, 0);
    memcpy(
        ZSTR_VAL(returnval),
        signature,
        signatureLen
    );
    RETURN_STR(returnval);
 
    efree(signature);
}


PHP_METHOD(Key, verify) {

    CK_RV rv;
    zend_long mechanismId;
    zend_string *data;
    zend_string *signature;
    zval *mechanismArgument = NULL;

    ZEND_PARSE_PARAMETERS_START(3,4)
        Z_PARAM_LONG(mechanismId)
        Z_PARAM_STR(data)
        Z_PARAM_STR(signature)
        Z_PARAM_OPTIONAL
        Z_PARAM_ZVAL(mechanismArgument)
    ZEND_PARSE_PARAMETERS_END();

    CK_MECHANISM mechanism = {mechanismId, NULL_PTR, 0};
    CK_VOID_PTR pParams;

    if (mechanismArgument) {
        if(zend_string_equals_literal(Z_OBJ_P(mechanismArgument)->ce->name, "Pkcs11\\RsaPssParams")) {
            pkcs11_rsapssparams_object *mechanismObj = Z_PKCS11_RSAPSSPARAMS_P(mechanismArgument);
            mechanism.pParameter = &mechanismObj->params;
            mechanism.ulParameterLen = sizeof(mechanismObj->params);
        }
    }

    pkcs11_key_object *objval = Z_PKCS11_KEY_P(ZEND_THIS);
    rv = objval->session->pkcs11->functionList->C_VerifyInit(
        objval->session->session,
        &mechanism,
        objval->key
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to verify");
        return;
    }

    CK_ULONG signatureLen;
    rv = objval->session->pkcs11->functionList->C_Verify(
        objval->session->session,
        ZSTR_VAL(data),
        ZSTR_LEN(data),
        ZSTR_VAL(signature),
        ZSTR_LEN(signature)
    );

    if (rv == CKR_SIGNATURE_INVALID) {
        RETURN_BOOL(false);
    }

    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to verify");
        return;
    }

    RETURN_BOOL(true);
}


PHP_METHOD(Key, encrypt) {

    CK_RV rv;
    zend_long mechanismId;
    zend_string *plaintext;
    zval *mechanismArgument = NULL;

    ZEND_PARSE_PARAMETERS_START(2,3)
        Z_PARAM_LONG(mechanismId)
        Z_PARAM_STR(plaintext)
        Z_PARAM_OPTIONAL
        Z_PARAM_ZVAL(mechanismArgument)
    ZEND_PARSE_PARAMETERS_END();

    CK_MECHANISM mechanism = {mechanismId, NULL_PTR, 0};

    if (mechanismArgument) {
        if (Z_TYPE_P(mechanismArgument) == IS_STRING) {
            mechanism.pParameter = Z_STRVAL_P(mechanismArgument);
            mechanism.ulParameterLen = Z_STRLEN_P(mechanismArgument);

        } else if (Z_TYPE_P(mechanismArgument) == IS_OBJECT) {
            if(zend_string_equals_literal(Z_OBJ_P(mechanismArgument)->ce->name, "Pkcs11\\GcmParams")) {
                pkcs11_gcmparams_object *mechanismObj = Z_PKCS11_GCMPARAMS_P(mechanismArgument);
                mechanism.pParameter = &mechanismObj->params;
                mechanism.ulParameterLen = sizeof(mechanismObj->params);
            
            } else if(zend_string_equals_literal(Z_OBJ_P(mechanismArgument)->ce->name, "Pkcs11\\RsaOaepParams")) {
                pkcs11_rsaoaepparams_object *mechanismObj = Z_PKCS11_RSAOAEPPARAMS_P(mechanismArgument);
                mechanism.pParameter = &mechanismObj->params;
                mechanism.ulParameterLen = sizeof(mechanismObj->params);
            }
        }
    }

    pkcs11_key_object *objval = Z_PKCS11_KEY_P(ZEND_THIS);
    rv = objval->session->pkcs11->functionList->C_EncryptInit(
        objval->session->session,
        &mechanism,
        objval->key
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to encrypt");
        return;
    }

    CK_ULONG ciphertextLen;
    rv = objval->session->pkcs11->functionList->C_Encrypt(
        objval->session->session,
        ZSTR_VAL(plaintext),
        ZSTR_LEN(plaintext),
        NULL_PTR ,
        &ciphertextLen
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to encrypt");
        return;
    }

    CK_BYTE_PTR ciphertext = ecalloc(ciphertextLen, sizeof(CK_BYTE));
    rv = objval->session->pkcs11->functionList->C_Encrypt(
        objval->session->session,
        ZSTR_VAL(plaintext),
        ZSTR_LEN(plaintext),
        ciphertext,
        &ciphertextLen
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to encrypt");
        return;
    }

    zend_string *returnval;
    returnval = zend_string_alloc(ciphertextLen, 0);
    memcpy(
        ZSTR_VAL(returnval),
        ciphertext,
        ciphertextLen
    );
    RETURN_STR(returnval);

    efree(ciphertext);
}


PHP_METHOD(Key, decrypt) {

    CK_RV rv;
    zend_long mechanismId;
    zend_string *ciphertext;
    zval *mechanismArgument = NULL;

    ZEND_PARSE_PARAMETERS_START(2,3)
        Z_PARAM_LONG(mechanismId)
        Z_PARAM_STR(ciphertext)
        Z_PARAM_OPTIONAL
        Z_PARAM_ZVAL(mechanismArgument)
    ZEND_PARSE_PARAMETERS_END();

    CK_MECHANISM mechanism = {mechanismId, NULL_PTR, 0};

    if (mechanismArgument) {
        if (Z_TYPE_P(mechanismArgument) == IS_STRING) {
            mechanism.pParameter = Z_STRVAL_P(mechanismArgument);
            mechanism.ulParameterLen = Z_STRLEN_P(mechanismArgument);

        } else if (Z_TYPE_P(mechanismArgument) == IS_OBJECT) {
            if(zend_string_equals_literal(Z_OBJ_P(mechanismArgument)->ce->name, "Pkcs11\\GcmParams")) {
                pkcs11_gcmparams_object *mechanismObj = Z_PKCS11_GCMPARAMS_P(mechanismArgument);
                mechanism.pParameter = &mechanismObj->params;
                mechanism.ulParameterLen = sizeof(mechanismObj->params);
            
            } else if(zend_string_equals_literal(Z_OBJ_P(mechanismArgument)->ce->name, "Pkcs11\\RsaOaepParams")) {
                pkcs11_rsaoaepparams_object *mechanismObj = Z_PKCS11_RSAOAEPPARAMS_P(mechanismArgument);
                mechanism.pParameter = &mechanismObj->params;
                mechanism.ulParameterLen = sizeof(mechanismObj->params);
            }
        }
    }

    pkcs11_key_object *objval = Z_PKCS11_KEY_P(ZEND_THIS);
    rv = objval->session->pkcs11->functionList->C_DecryptInit(
        objval->session->session,
        &mechanism,
        objval->key
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to decrypt");
        return;
    }

    CK_ULONG plaintextLen;
    rv = objval->session->pkcs11->functionList->C_Decrypt(
        objval->session->session,
        ZSTR_VAL(ciphertext),
        ZSTR_LEN(ciphertext),
        NULL_PTR,
        &plaintextLen
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to decrypt");
        return;
    }

    CK_BYTE_PTR plaintext = ecalloc(plaintextLen, sizeof(CK_BYTE));
    rv = objval->session->pkcs11->functionList->C_Decrypt(
        objval->session->session,
        ZSTR_VAL(ciphertext),
        ZSTR_LEN(ciphertext),
        plaintext,
        &plaintextLen
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to decrypt");
        return;
    }

    zend_string *returnval;
    returnval = zend_string_alloc(plaintextLen, 0);
    memcpy(
        ZSTR_VAL(returnval),
        plaintext,
        plaintextLen
    );
    RETURN_STR(returnval);

    efree(plaintext);
}


PHP_METHOD(Key, wrap) {

    CK_RV rv;
    zend_long mechanismId;
    zval *key;
    zval *mechanismArgument = NULL;

    ZEND_PARSE_PARAMETERS_START(2,3)
        Z_PARAM_LONG(mechanismId)
        Z_PARAM_ZVAL(key)
        Z_PARAM_OPTIONAL
        Z_PARAM_ZVAL(mechanismArgument)
    ZEND_PARSE_PARAMETERS_END();

    CK_MECHANISM mechanism = {mechanismId, NULL_PTR, 0};

    if (mechanismArgument) {
        if (Z_TYPE_P(mechanismArgument) == IS_STRING) {
            mechanism.pParameter = Z_STRVAL_P(mechanismArgument);
            mechanism.ulParameterLen = Z_STRLEN_P(mechanismArgument);

        } else if (Z_TYPE_P(mechanismArgument) == IS_OBJECT) {
            if(zend_string_equals_literal(Z_OBJ_P(mechanismArgument)->ce->name, "Pkcs11\\GcmParams")) {
                pkcs11_gcmparams_object *mechanismObj = Z_PKCS11_GCMPARAMS_P(mechanismArgument);
                mechanism.pParameter = &mechanismObj->params;
                mechanism.ulParameterLen = sizeof(mechanismObj->params);
            
            } else if(zend_string_equals_literal(Z_OBJ_P(mechanismArgument)->ce->name, "Pkcs11\\RsaOaepParams")) {
                pkcs11_rsaoaepparams_object *mechanismObj = Z_PKCS11_RSAOAEPPARAMS_P(mechanismArgument);
                mechanism.pParameter = &mechanismObj->params;
                mechanism.ulParameterLen = sizeof(mechanismObj->params);
            }
        }
    }

    CK_ULONG ciphertextLen;
    pkcs11_key_object *objval = Z_PKCS11_KEY_P(ZEND_THIS);
    pkcs11_key_object *keyobjval = Z_PKCS11_KEY_P(key);
    rv = objval->session->pkcs11->functionList->C_WrapKey(
        objval->session->session,
        &mechanism,
        objval->key,
        keyobjval->key,
        NULL_PTR ,
        &ciphertextLen
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to wrap");
        return;
    }

    CK_BYTE_PTR ciphertext = ecalloc(ciphertextLen, sizeof(CK_BYTE));
    rv = objval->session->pkcs11->functionList->C_WrapKey(
        objval->session->session,
        &mechanism,
        objval->key,
        keyobjval->key,
        ciphertext,
        &ciphertextLen
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to wrap");
        return;
    }

    zend_string *returnval;
    returnval = zend_string_alloc(ciphertextLen, 0);
    memcpy(
        ZSTR_VAL(returnval),
        ciphertext,
        ciphertextLen
    );
    RETURN_STR(returnval);

    efree(ciphertext);
}


PHP_METHOD(Key, unwrap) {

    CK_RV rv;
    zend_long mechanismId;
    zend_string *ciphertext;
    HashTable *template;
    zval *mechanismArgument = NULL;

    ZEND_PARSE_PARAMETERS_START(3,4)
        Z_PARAM_LONG(mechanismId)
        Z_PARAM_STR(ciphertext)
        Z_PARAM_ARRAY_HT(template)
        Z_PARAM_OPTIONAL
        Z_PARAM_ZVAL(mechanismArgument)
    ZEND_PARSE_PARAMETERS_END();

    int templateItemCount;
    CK_ATTRIBUTE_PTR templateObj;
    parseTemplate(&template, &templateObj, &templateItemCount);

    CK_MECHANISM mechanism = {mechanismId, NULL_PTR, 0};
    CK_OBJECT_HANDLE uhKey;

    if (mechanismArgument) {
        if (Z_TYPE_P(mechanismArgument) == IS_STRING) {
            mechanism.pParameter = Z_STRVAL_P(mechanismArgument);
            mechanism.ulParameterLen = Z_STRLEN_P(mechanismArgument);

        } else if (Z_TYPE_P(mechanismArgument) == IS_OBJECT) {
            if(zend_string_equals_literal(Z_OBJ_P(mechanismArgument)->ce->name, "Pkcs11\\GcmParams")) {
                pkcs11_gcmparams_object *mechanismObj = Z_PKCS11_GCMPARAMS_P(mechanismArgument);
                mechanism.pParameter = &mechanismObj->params;
                mechanism.ulParameterLen = sizeof(mechanismObj->params);
            
            } else if(zend_string_equals_literal(Z_OBJ_P(mechanismArgument)->ce->name, "Pkcs11\\RsaOaepParams")) {
                pkcs11_rsaoaepparams_object *mechanismObj = Z_PKCS11_RSAOAEPPARAMS_P(mechanismArgument);
                mechanism.pParameter = &mechanismObj->params;
                mechanism.ulParameterLen = sizeof(mechanismObj->params);
            }
        }
    }

    pkcs11_key_object *objval = Z_PKCS11_KEY_P(ZEND_THIS);
    rv = objval->session->pkcs11->functionList->C_UnwrapKey(
        objval->session->session,
        &mechanism,
        objval->key,
        ZSTR_VAL(ciphertext),
        ZSTR_LEN(ciphertext),
        templateObj,
        templateItemCount,
        &uhKey
    );
    freeTemplate(templateObj);
    
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to unwrap");
        return;
    }

    pkcs11_key_object* key_obj;

    object_init_ex(return_value, ce_Pkcs11_Key);
    key_obj = Z_PKCS11_KEY_P(return_value);
    key_obj->session = objval->session;
    key_obj->key = uhKey;
}


PHP_METHOD(Key, derive) {

    CK_RV rv;
    zend_long mechanismId;
    zval *mechanismArgument = NULL;
    HashTable *template;

    ZEND_PARSE_PARAMETERS_START(3,3)
        Z_PARAM_LONG(mechanismId)
        Z_PARAM_ZVAL(mechanismArgument)
        Z_PARAM_ARRAY_HT(template)
    ZEND_PARSE_PARAMETERS_END();

    CK_MECHANISM mechanism = {mechanismId, NULL_PTR, 0};
    CK_VOID_PTR pParams;
    CK_OBJECT_HANDLE phKey;

    int templateItemCount;
    CK_ATTRIBUTE_PTR templateObj;
    parseTemplate(&template, &templateObj, &templateItemCount);

    if (mechanismArgument) {
        if(zend_string_equals_literal(Z_OBJ_P(mechanismArgument)->ce->name, "Pkcs11\\Ecdh1DeriveParams")) {
            pkcs11_ecdh1deriveparams_object *mechanismObj = Z_PKCS11_ECDH1DERIVEPARAMS_P(mechanismArgument);
            mechanism.pParameter = &mechanismObj->params;
            mechanism.ulParameterLen = sizeof(mechanismObj->params);
        }
    }

    pkcs11_key_object *objval = Z_PKCS11_KEY_P(ZEND_THIS);
    rv = objval->session->pkcs11->functionList->C_DeriveKey(
        objval->session->session,
        &mechanism,
        objval->key,
        templateObj,
        templateItemCount,
        &phKey
    );
    freeTemplate(templateObj);

    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to derive");
        return;
    }

    pkcs11_key_object* key_obj;

    object_init_ex(return_value, ce_Pkcs11_Key);
    key_obj = Z_PKCS11_KEY_P(return_value);
    key_obj->session = objval->session;
    key_obj->key = phKey;
}


void pkcs11_key_shutdown(pkcs11_key_object *obj) {
}

static zend_function_entry key_class_functions[] = {
    PHP_ME(Key, initializeSignature, arginfo_initializeSignature, ZEND_ACC_PUBLIC)
    PHP_ME(Key, encrypt,             arginfo_encrypt,             ZEND_ACC_PUBLIC)
    PHP_ME(Key, decrypt,             arginfo_decrypt,             ZEND_ACC_PUBLIC)
    PHP_ME(Key, wrap,                arginfo_wrap,                ZEND_ACC_PUBLIC)
    PHP_ME(Key, unwrap,              arginfo_unwrap,              ZEND_ACC_PUBLIC)
    PHP_ME(Key, sign,                arginfo_sign,                ZEND_ACC_PUBLIC)
    PHP_ME(Key, verify,              arginfo_verify,              ZEND_ACC_PUBLIC)
    PHP_ME(Key, derive,              arginfo_derive,              ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static zend_object *pkcs11_key_ctor(zend_class_entry *ce) {
    pkcs11_key_object *objval = zend_object_alloc(sizeof(pkcs11_key_object), ce);

    zend_object_std_init(&objval->std, ce);
    object_properties_init(&objval->std, ce);
    objval->std.handlers = &pkcs11_key_handlers;

    return &objval->std;
}
static void pkcs11_key_dtor(zend_object *zobj) {
    pkcs11_key_object *objval = pkcs11_key_from_zend_object(zobj);
    pkcs11_key_shutdown(objval);
    zend_object_std_dtor(&objval->std);
}
void register_pkcs11_key() {
    zend_class_entry ce;
    memcpy(&pkcs11_key_handlers, &std_object_handlers, sizeof(zend_object_handlers));
    INIT_NS_CLASS_ENTRY(ce, "Pkcs11", "Key", key_class_functions);
    ce.create_object = pkcs11_key_ctor;
    pkcs11_key_handlers.offset = XtOffsetOf(pkcs11_key_object, std);
    pkcs11_key_handlers.clone_obj = NULL;
    pkcs11_key_handlers.free_obj = pkcs11_key_dtor;
    ce_Pkcs11_Key = zend_register_internal_class_ex(&ce, ce_Pkcs11_P11Object);
    ce_Pkcs11_Key->serialize = zend_class_serialize_deny;
    ce_Pkcs11_Key->unserialize = zend_class_unserialize_deny;
}