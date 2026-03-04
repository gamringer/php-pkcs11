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

zend_class_entry *ce_Pkcs11_RsaOaepParams;
static zend_object_handlers pkcs11_rsaoaepparams_handlers;


ZEND_BEGIN_ARG_INFO_EX(arginfo___construct, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, mechanismId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, mgfId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, source, IS_STRING, 1)
ZEND_END_ARG_INFO()

PHP_METHOD(RsaOaepParams, __construct) {

    CK_RV rv;
    zend_long mechanismId;
    zend_long mgfId;
    zend_string *source = NULL;

    ZEND_PARSE_PARAMETERS_START(2,3)
        Z_PARAM_LONG(mechanismId)
        Z_PARAM_LONG(mgfId)
        Z_PARAM_OPTIONAL
        Z_PARAM_STR(source)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_rsaoaepparams_object *objval = Z_PKCS11_RSAOAEPPARAMS_P(ZEND_THIS);
    objval->params.hashAlg = mechanismId;
    objval->params.mgf = mgfId;
    objval->params.source = CKZ_DATA_SPECIFIED;
    if (source && ZSTR_LEN(source) > 0) {
        objval->params.pSourceData = ZSTR_VAL(source);
        objval->params.ulSourceDataLen = ZSTR_LEN(source);
    }
}


void pkcs11_rsaoaepparams_shutdown(pkcs11_rsaoaepparams_object *obj) {
}

static zend_function_entry rsaoaepparams_class_functions[] = {
    PHP_ME(RsaOaepParams, __construct, arginfo___construct, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    PHP_FE_END
};


DEFINE_MAGIC_FUNCS(pkcs11_rsaoaepparams, rsaoaepparams, RsaOaepParams)
