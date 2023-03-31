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

zend_class_entry *ce_Pkcs11_AwsGcmParams;
static zend_object_handlers pkcs11_awsgcmparams_handlers;


ZEND_BEGIN_ARG_INFO_EX(arginfo___construct, 0, 0, 3)
    ZEND_ARG_TYPE_INFO(0, aad, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, sTagLen, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(AwsGcmParams, __construct) {

    CK_RV rv;
    zend_string *aad;
    zend_long sTagLen;

    ZEND_PARSE_PARAMETERS_START(2,2)
        Z_PARAM_STR(aad)
        Z_PARAM_LONG(sTagLen)
    ZEND_PARSE_PARAMETERS_END();

    CK_BYTE_PTR iv = malloc(12);
    if (NULL == iv) {
        pkcs11_error(rv, "Failed to allocate memory for AWS IV");
        return;
    }
    memset(iv, 0, 12);

    pkcs11_awsgcmparams_object *objval = Z_PKCS11_AWSGCMPARAMS_P(ZEND_THIS);
    objval->params.pIv = iv;
    objval->params.ulIvLen = 12;
    objval->params.pAAD = ZSTR_VAL(aad);
    objval->params.ulAADLen = ZSTR_LEN(aad);
    objval->params.ulTagBits = sTagLen;
}


void pkcs11_awsgcmparams_shutdown(pkcs11_awsgcmparams_object *obj) {
}

static zend_function_entry awsgcmparams_class_functions[] = {
    PHP_ME(AwsGcmParams, __construct, arginfo___construct, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    PHP_FE_END
};


DEFINE_MAGIC_FUNCS(pkcs11_awsgcmparams, awsgcmparams, AwsGcmParams)
