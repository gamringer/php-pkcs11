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

    rv = objval->key->session->pkcs11->functionList->C_VerifyUpdate(
        objval->key->session->session,
        ZSTR_VAL(data),
        ZSTR_LEN(data)
    );
    if (rv != CKR_OK) {
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

    rv = objval->key->session->pkcs11->functionList->C_VerifyFinal(
        objval->key->session->session,
        ZSTR_VAL(signature),
        ZSTR_LEN(signature)
    );

    if (rv == CKR_SIGNATURE_INVALID || rv == CKR_SIGNATURE_LEN_RANGE) {
        RETURN_BOOL(false);
    }

    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to finalize verification");
        return;
    }

    RETURN_BOOL(true);
}

void pkcs11_verificationcontext_shutdown(pkcs11_verificationcontext_object *obj) {
}

static zend_function_entry verificationcontext_class_functions[] = {
    PHP_ME(VerificationContext, update, arginfo_update, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    PHP_ME(VerificationContext, finalize, arginfo_finalize, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    PHP_FE_END
};


DEFINE_MAGIC_FUNCS(pkcs11_verificationcontext, verificationcontext, VerificationContext)
