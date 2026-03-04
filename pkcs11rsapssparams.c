/*
   +----------------------------------------------------------------------+
   | PHP PKCS11                                                           |
   +----------------------------------------------------------------------+
   | Copyright (c) Guillaume Amringer                                     |
   +----------------------------------------------------------------------+
   | This source file is subject to the MIT license, that is bundled with |
   | this package in the file LICENSE, and is available through the at    |
   | the following url: https://mit-license.org/                          |
   +----------------------------------------------------------------------+
   | Author: Guillaume Amringer                                           |
   +----------------------------------------------------------------------+
*/

#include "pkcs11int.h"

zend_class_entry *ce_Pkcs11_RsaPssParams;
static zend_object_handlers pkcs11_rsapssparams_handlers;


ZEND_BEGIN_ARG_INFO_EX(arginfo___construct, 0, 0, 3)
    ZEND_ARG_TYPE_INFO(0, mechanismId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, mgfId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, sLen, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(RsaPssParams, __construct) {

    CK_RV rv;
    zend_long mechanismId;
    zend_long mgfId;
    zend_long sLen;

    ZEND_PARSE_PARAMETERS_START(3,3)
        Z_PARAM_LONG(mechanismId)
        Z_PARAM_LONG(mgfId)
        Z_PARAM_LONG(sLen)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_rsapssparams_object *objval = Z_PKCS11_RSAPSSPARAMS_P(ZEND_THIS);
    objval->params.hashAlg = mechanismId;
    objval->params.mgf = mgfId;
    objval->params.sLen = sLen;
}


void pkcs11_rsapssparams_shutdown(pkcs11_rsapssparams_object *obj) {
}

static zend_function_entry rsapssparams_class_functions[] = {
    PHP_ME(RsaPssParams, __construct, arginfo___construct, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    PHP_FE_END
};


DEFINE_MAGIC_FUNCS(pkcs11_rsapssparams, rsapssparams, RsaPssParams)
