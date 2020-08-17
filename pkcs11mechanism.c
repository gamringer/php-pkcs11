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

zend_class_entry *ce_Pkcs11_Mechanism;
static zend_object_handlers pkcs11_mechanism_handlers;


ZEND_BEGIN_ARG_INFO_EX(arginfo___construct, 0, 0, 3)
    ZEND_ARG_TYPE_INFO(0, mechanismId, IS_LONG, 0)
    ZEND_ARG_INFO(0, mechanismArgument)
ZEND_END_ARG_INFO()

PHP_METHOD(Mechanism, __construct) {

    CK_RV rv;
    zend_long mechanismId;
    zval *mechanismArgument = NULL;

    ZEND_PARSE_PARAMETERS_START(1,2)
        Z_PARAM_LONG(mechanismId)
        Z_PARAM_OPTIONAL
        Z_PARAM_ZVAL(mechanismArgument)
    ZEND_PARSE_PARAMETERS_END();
    
    pkcs11_mechanism_object *objval = Z_PKCS11_MECHANISM_P(ZEND_THIS);
    objval->mechanism.mechanism = mechanismId;

    if (mechanismArgument) {
        if (Z_TYPE_P(mechanismArgument) == IS_STRING) {
            objval->mechanism.pParameter = Z_STRVAL_P(mechanismArgument);
            objval->mechanism.ulParameterLen = Z_STRLEN_P(mechanismArgument);

        } else if (Z_TYPE_P(mechanismArgument) == IS_OBJECT) {
            if(zend_string_equals_literal(Z_OBJ_P(mechanismArgument)->ce->name, "Pkcs11\\GcmParams")) {
                pkcs11_gcmparams_object *mechanismParamsObj = Z_PKCS11_GCMPARAMS_P(mechanismArgument);
                objval->mechanism.pParameter = &mechanismParamsObj->params;
                objval->mechanism.ulParameterLen = sizeof(mechanismParamsObj->params);
            } else

            if(zend_string_equals_literal(Z_OBJ_P(mechanismArgument)->ce->name, "Pkcs11\\RsaOaepParams")) {
                pkcs11_rsaoaepparams_object *mechanismParamsObj = Z_PKCS11_RSAOAEPPARAMS_P(mechanismArgument);
                objval->mechanism.pParameter = &mechanismParamsObj->params;
                objval->mechanism.ulParameterLen = sizeof(mechanismParamsObj->params);
            } else

            if(zend_string_equals_literal(Z_OBJ_P(mechanismArgument)->ce->name, "Pkcs11\\RsaPssParams")) {
                pkcs11_rsapssparams_object *mechanismParamsObj = Z_PKCS11_RSAPSSPARAMS_P(mechanismArgument);
                objval->mechanism.pParameter = &mechanismParamsObj->params;
                objval->mechanism.ulParameterLen = sizeof(mechanismParamsObj->params);
            } else


            if(zend_string_equals_literal(Z_OBJ_P(mechanismArgument)->ce->name, "Pkcs11\\Ecdh1DeriveParams")) {
                pkcs11_ecdh1deriveparams_object *mechanismParamsObj = Z_PKCS11_ECDH1DERIVEPARAMS_P(mechanismArgument);
                objval->mechanism.pParameter = &mechanismParamsObj->params;
                objval->mechanism.ulParameterLen = sizeof(mechanismParamsObj->params);
            }
        }
    }
}


void pkcs11_mechanism_shutdown(pkcs11_mechanism_object *obj) {
}

static zend_function_entry mechanism_class_functions[] = {
    PHP_ME(Mechanism, __construct, arginfo___construct, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    PHP_FE_END
};


DEFINE_MAGIC_FUNCS(pkcs11_mechanism, mechanism, Mechanism)
