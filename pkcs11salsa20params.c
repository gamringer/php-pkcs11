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

zend_class_entry *ce_Pkcs11_Salsa20Params;
static zend_object_handlers pkcs11_salsa20params_handlers;


ZEND_BEGIN_ARG_INFO_EX(arginfo___construct, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, nonce, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, blockCounter, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Salsa20Params, __construct) {

    CK_RV rv;
    zend_string *nonce;
    zend_string *blockCounter = NULL;
    zend_long sTagLen;

    ZEND_PARSE_PARAMETERS_START(1,2)
        Z_PARAM_STR(nonce)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(sTagLen)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_salsa20params_object *objval = Z_PKCS11_SALSA20PARAMS_P(ZEND_THIS);
    objval->params.pNonce = ZSTR_VAL(nonce);
    objval->params.ulNonceBits = ZSTR_LEN(nonce) * 8;
    if (blockCounter) {
      objval->params.pBlockCounter = ZSTR_VAL(blockCounter);
    }
}


void pkcs11_salsa20params_shutdown(pkcs11_salsa20params_object *obj) {
}

static zend_function_entry salsa20params_class_functions[] = {
    PHP_ME(Salsa20Params, __construct, arginfo___construct, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    PHP_FE_END
};


DEFINE_MAGIC_FUNCS(pkcs11_salsa20params, salsa20params, Salsa20Params)
