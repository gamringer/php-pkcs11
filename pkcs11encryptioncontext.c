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

zend_class_entry *ce_Pkcs11_EncryptionContext;
static zend_object_handlers pkcs11_encryptioncontext_handlers;

ZEND_BEGIN_ARG_INFO_EX(arginfo_update, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_finalize, 0, 0, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(EncryptionContext, update) {

    CK_RV rv;
    zend_string *data;

    ZEND_PARSE_PARAMETERS_START(1,1)
        Z_PARAM_STR(data)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_encryptioncontext_object *objval = Z_PKCS11_ENCRYPTIONCONTEXT_P(ZEND_THIS);

    CK_ULONG ciphertextLen;
    rv = objval->key->session->pkcs11->functionList->C_EncryptUpdate(
        objval->key->session->session,
        ZSTR_VAL(data),
        ZSTR_LEN(data),
        NULL_PTR ,
        &ciphertextLen
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to update encryption");
        return;
    }

    CK_BYTE_PTR ciphertext = ecalloc(ciphertextLen, sizeof(CK_BYTE));
    rv = objval->key->session->pkcs11->functionList->C_EncryptUpdate(
        objval->key->session->session,
        ZSTR_VAL(data),
        ZSTR_LEN(data),
        ciphertext,
        &ciphertextLen
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to update encryption");
        return;
    }

    zend_string *returnval;
    returnval = zend_string_alloc(ciphertextLen, 0);
    memcpy(
        ZSTR_VAL(returnval),
        ciphertext,
        ciphertextLen
    );
    efree(ciphertext);

    RETURN_STR(returnval);
}

PHP_METHOD(EncryptionContext, finalize) {

    CK_RV rv;

    ZEND_PARSE_PARAMETERS_START(0,0)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_encryptioncontext_object *objval = Z_PKCS11_ENCRYPTIONCONTEXT_P(ZEND_THIS);

    CK_ULONG ciphertextLen;
    rv = objval->key->session->pkcs11->functionList->C_EncryptFinal(
        objval->key->session->session,
        NULL_PTR ,
        &ciphertextLen
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to finalize encryption");
        return;
    }

    CK_BYTE_PTR ciphertext = ecalloc(ciphertextLen, sizeof(CK_BYTE));
    rv = objval->key->session->pkcs11->functionList->C_EncryptFinal(
        objval->key->session->session,
        ciphertext,
        &ciphertextLen
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to finalize encryption");
        return;
    }

    zend_string *returnval;
    returnval = zend_string_alloc(ciphertextLen, 0);
    memcpy(
        ZSTR_VAL(returnval),
        ciphertext,
        ciphertextLen
    );
    efree(ciphertext);

    RETURN_STR(returnval);
}

void pkcs11_encryptioncontext_shutdown(pkcs11_encryptioncontext_object *obj) {
    GC_DELREF(&obj->key->std);
}

static zend_function_entry encryptioncontext_class_functions[] = {
    PHP_ME(EncryptionContext, update, arginfo_update, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    PHP_ME(EncryptionContext, finalize, arginfo_finalize, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    PHP_FE_END
};


DEFINE_MAGIC_FUNCS(pkcs11_encryptioncontext, encryptioncontext, EncryptionContext)
