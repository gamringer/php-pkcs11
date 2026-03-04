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

zend_class_entry *ce_Pkcs11_ChaCha20Params;
static zend_object_handlers pkcs11_chacha20params_handlers;


ZEND_BEGIN_ARG_INFO_EX(arginfo___construct, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, nonce, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, blockCounter, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(ChaCha20Params, __construct) {

    CK_RV rv;
    zend_string *nonce;
    zend_string *blockCounter = NULL;

    ZEND_PARSE_PARAMETERS_START(1,2)
        Z_PARAM_STR(nonce)
        Z_PARAM_OPTIONAL
        Z_PARAM_STR(blockCounter)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_chacha20params_object *objval = Z_PKCS11_CHACHA20PARAMS_P(ZEND_THIS);
    objval->params.pNonce = ZSTR_VAL(nonce);
    objval->params.ulNonceBits = ZSTR_LEN(nonce) * 8;
    if (blockCounter) {
        objval->params.pBlockCounter = ZSTR_VAL(blockCounter);
        objval->params.blockCounterBits = ZSTR_LEN(blockCounter) * 8;
    }
}


void pkcs11_chacha20params_shutdown(pkcs11_chacha20params_object *obj) {
}

static zend_function_entry chacha20params_class_functions[] = {
    PHP_ME(ChaCha20Params, __construct, arginfo___construct, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    PHP_FE_END
};


DEFINE_MAGIC_FUNCS(pkcs11_chacha20params, chacha20params, ChaCha20Params)
