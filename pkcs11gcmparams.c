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

zend_class_entry *ce_Pkcs11_GcmParams;
static zend_object_handlers pkcs11_gcmparams_handlers;


ZEND_BEGIN_ARG_INFO_EX(arginfo___construct, 0, 0, 3)
    ZEND_ARG_TYPE_INFO(0, iv, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, aad, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, sTagLen, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(GcmParams, __construct) {

    CK_RV rv;
    zend_string *iv;
    zend_string *aad;
    zend_long sTagLen;

    ZEND_PARSE_PARAMETERS_START(3,3)
        Z_PARAM_STR(iv)
        Z_PARAM_STR(aad)
        Z_PARAM_LONG(sTagLen)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_gcmparams_object *objval = Z_PKCS11_GCMPARAMS_P(ZEND_THIS);
    objval->params.pIv = ZSTR_VAL(iv);
    objval->params.ulIvLen = ZSTR_LEN(iv);
    objval->params.pAAD = ZSTR_VAL(aad);
    objval->params.ulAADLen = ZSTR_LEN(aad);
    objval->params.ulTagBits = sTagLen;
}


void pkcs11_gcmparams_shutdown(pkcs11_gcmparams_object *obj) {
}

static zend_function_entry gcmparams_class_functions[] = {
    PHP_ME(GcmParams, __construct, arginfo___construct, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    PHP_FE_END
};


DEFINE_MAGIC_FUNCS(pkcs11_gcmparams, gcmparams, GcmParams)
