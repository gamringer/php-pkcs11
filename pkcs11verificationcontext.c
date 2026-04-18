/*
   +----------------------------------------------------------------------+
   | PHP PKCS11                                                           |
   +----------------------------------------------------------------------+
   | Copyright (c) Guillaume Amringer                                     |
   +----------------------------------------------------------------------+
   | This source file is subject to the MIT license, that is bundled with |
   | this package in the file LICENSE, and is available at the following  |
   | url: https://mit-license.org/                                        |
   +----------------------------------------------------------------------+
   | Author: Guillaume Amringer                                           |
   +----------------------------------------------------------------------+
*/

#include "pkcs11int.h"

zend_class_entry *ce_Pkcs11_VerificationContext;
static zend_object_handlers pkcs11_verificationcontext_handlers;

ZEND_BEGIN_ARG_INFO_EX(arginfo_update, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_finalize, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, signature, IS_STRING, 1)
ZEND_END_ARG_INFO()

PHP_METHOD(VerificationContext, update) {

    CK_RV rv;
    zend_string *data;

    ZEND_PARSE_PARAMETERS_START(1,1)
        Z_PARAM_STR(data)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_verificationcontext_object *objval = Z_PKCS11_VERIFICATIONCONTEXT_P(ZEND_THIS);

    PKCS11_SESSION_EVICT(objval->key->session, rv,
        objval->key->session->pkcs11->functionList->C_VerifyUpdate(
            objval->key->session->session,
            ZSTR_VAL(data),
            ZSTR_LEN(data)
        )
    );
    if (rv != CKR_OK) {
        objval->key->session->tainted = false;
        pkcs11_error(rv, "Unable to update verification");
        return;
    }
}

PHP_METHOD(VerificationContext, finalize) {

    CK_RV rv;
    zend_string *signature;

    ZEND_PARSE_PARAMETERS_START(1,1)
        Z_PARAM_STR(signature)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_verificationcontext_object *objval = Z_PKCS11_VERIFICATIONCONTEXT_P(ZEND_THIS);

    PKCS11_SESSION_EVICT(objval->key->session, rv,
        objval->key->session->pkcs11->functionList->C_VerifyFinal(
            objval->key->session->session,
            ZSTR_VAL(signature),
            ZSTR_LEN(signature)
        )
    );

    if (rv == CKR_SIGNATURE_INVALID || rv == CKR_SIGNATURE_LEN_RANGE) {
        objval->key->session->tainted = false;
        RETURN_BOOL(false);
    }

    if (rv != CKR_OK) {
        objval->key->session->tainted = false;
        pkcs11_error(rv, "Unable to finalize verification");
        return;
    }

    objval->key->session->tainted = false;
    RETURN_BOOL(true);
}

void pkcs11_verificationcontext_shutdown(pkcs11_verificationcontext_object *obj) {
    GC_DELREF(&obj->key->std);
}

static zend_function_entry verificationcontext_class_functions[] = {
    PHP_ME(VerificationContext, update, arginfo_update, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    PHP_ME(VerificationContext, finalize, arginfo_finalize, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    PHP_FE_END
};


DEFINE_MAGIC_FUNCS(pkcs11_verificationcontext, verificationcontext, VerificationContext)
