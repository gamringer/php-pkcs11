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

zend_class_entry *ce_Pkcs11_Ecdh1DeriveParams;
static zend_object_handlers pkcs11_ecdh1deriveparams_handlers;


ZEND_BEGIN_ARG_INFO_EX(arginfo___construct, 0, 0, 3)
    ZEND_ARG_TYPE_INFO(0, kdfId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, sharedData, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, publicData, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Ecdh1DeriveParams, __construct) {

    CK_RV rv;
    zend_long kdfId;
    zend_string *sharedData;
    zend_string *publicData;

    ZEND_PARSE_PARAMETERS_START(3,3)
        Z_PARAM_LONG(kdfId)
        Z_PARAM_STR(sharedData)
        Z_PARAM_STR(publicData)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_ecdh1deriveparams_object *objval = Z_PKCS11_ECDH1DERIVEPARAMS_P(ZEND_THIS);
    objval->params.kdf = kdfId;
    objval->params.pSharedData = NULL;//ZSTR_VAL(sharedData);
    objval->params.ulSharedDataLen = 0;//ZSTR_LEN(sharedData);
    objval->params.pPublicData = ZSTR_VAL(publicData);
    objval->params.ulPublicDataLen = ZSTR_LEN(publicData);
}

void pkcs11_ecdh1deriveparams_shutdown(pkcs11_ecdh1deriveparams_object *obj) {
}

static zend_function_entry ecdh1deriveparams_class_functions[] = {
    PHP_ME(Ecdh1DeriveParams, __construct, arginfo___construct, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    PHP_FE_END
};


DEFINE_MAGIC_FUNCS(pkcs11_ecdh1deriveparams, ecdh1deriveparams, Ecdh1DeriveParams)
