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

zend_class_entry *ce_Pkcs11_P11Object;
static zend_object_handlers pkcs11_object_handlers;


ZEND_BEGIN_ARG_INFO_EX(arginfo_getAttributeValue, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, attributeIds, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_getSize, 0, 0, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Object, getAttributeValue) {

    CK_RV rv;
    zval *attributeIds;
    zval *attributeId;
    unsigned int i;

    ZEND_PARSE_PARAMETERS_START(1,1)
        Z_PARAM_ARRAY(attributeIds)
    ZEND_PARSE_PARAMETERS_END();

    int attributeIdCount = zend_hash_num_elements(Z_ARRVAL_P(attributeIds));

    CK_ATTRIBUTE_PTR template = (CK_ATTRIBUTE *) ecalloc(sizeof(CK_ATTRIBUTE), attributeIdCount);

    i = 0;
    ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(attributeIds), attributeId) {
        if (Z_TYPE_P(attributeId) != IS_LONG) {
            general_error("PKCS11 module error", "Unable to get attribute value. Attribute ID must be an integer");
            return;
        }
        template[i] = (CK_ATTRIBUTE) {zval_get_long(attributeId), NULL_PTR, 0};
        i++;
    } ZEND_HASH_FOREACH_END();

    pkcs11_object_object *objval = Z_PKCS11_OBJECT_P(ZEND_THIS);
    rv = objval->session->pkcs11->functionList->C_GetAttributeValue(
        objval->session->session,
        objval->object,
        template,
        attributeIdCount
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to get attribute value");
        return;
    }

    for (i=0; i<attributeIdCount; i++) {
        template[i].pValue = (uint8_t *) ecalloc(1, template[i].ulValueLen);
    }

    rv = objval->session->pkcs11->functionList->C_GetAttributeValue(
        objval->session->session,
        objval->object,
        template,
        attributeIdCount
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to get attribute value");
        return;
    }

    array_init(return_value);
    for (i=0; i<attributeIdCount; i++) {

        if (template[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
            continue;
        }

        if (template[i].ulValueLen == 0) {
            add_index_null(return_value, template[i].type);
            continue;
        }

        zend_string *foo;
        foo = zend_string_alloc(template[i].ulValueLen, 0);
        memcpy(
            ZSTR_VAL(foo),
            template[i].pValue,
            template[i].ulValueLen
        );

        efree(template[i].pValue);

        add_index_str(return_value, template[i].type, foo);
    }

    efree(template);
}

PHP_METHOD(Object, getSize) {

    CK_RV rv;

    CK_ULONG ulSize;

    pkcs11_object_object *objval = Z_PKCS11_OBJECT_P(ZEND_THIS);
    rv = objval->session->pkcs11->functionList->C_GetObjectSize(
        objval->session->session,
        objval->object,
        &ulSize
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to get object size");
        return;
    }

    RETURN_LONG(ulSize);
}

void pkcs11_object_shutdown(pkcs11_object_object *obj) {
}

static zend_function_entry object_class_functions[] = {
    PHP_ME(Object, getAttributeValue, arginfo_getAttributeValue, ZEND_ACC_PUBLIC)
    PHP_ME(Object, getSize, arginfo_getSize, ZEND_ACC_PUBLIC)
    PHP_FE_END
};


DEFINE_MAGIC_FUNCS(pkcs11_object, object, P11Object)
