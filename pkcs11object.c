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

        if (template[i].type == CKA_CLASS
         || template[i].type == CKA_CERTIFICATE_TYPE
         || template[i].type == CKA_KEY_TYPE
         || template[i].type == CKA_OTP_SERVICE_LOGO_TYPE
         || template[i].type == CKA_HW_FEATURE_TYPE
         || template[i].type == CKA_MECHANISM_TYPE
         || template[i].type == CKA_NAME_HASH_ALGORITHM
         || template[i].type == CKA_MODULUS_BITS
         || template[i].type == CKA_PRIME_BITS
         || template[i].type == CKA_SUBPRIME_BITS
         || template[i].type == CKA_SUB_PRIME_BITS
         || template[i].type == CKA_SUBPRIME_BITS
         || template[i].type == CKA_VALUE_BITS
         || template[i].type == CKA_VALUE_LEN
         || template[i].type == CKA_KEY_GEN_MECHANISM
         || template[i].type == CKA_AUTH_PIN_FLAGS
         || template[i].type == CKA_OTP_FORMAT
         || template[i].type == CKA_OTP_LENGTH
         || template[i].type == CKA_OTP_TIME_INTERVAL
         || template[i].type == CKA_OTP_CHALLENGE_REQUIREMENT
         || template[i].type == CKA_OTP_TIME_REQUIREMENT
         || template[i].type == CKA_OTP_COUNTER_REQUIREMENT
         || template[i].type == CKA_OTP_PIN_REQUIREMENT
         || template[i].type == CKA_PIXEL_X
         || template[i].type == CKA_PIXEL_Y
         || template[i].type == CKA_RESOLUTION
         || template[i].type == CKA_CHAR_ROWS
         || template[i].type == CKA_CHAR_COLUMNS
         || template[i].type == CKA_BITS_PER_PIXEL
         || template[i].type == CKA_PROFILE_ID
         || template[i].type == CKA_X2RATCHET_BAGSIZE
         || template[i].type == CKA_X2RATCHET_NR
         || template[i].type == CKA_X2RATCHET_NS
         || template[i].type == CKA_X2RATCHET_PNS
         || template[i].type == CKA_CERTIFICATE_CATEGORY
         || template[i].type == CKA_JAVA_MIDP_SECURITY_DOMAIN
        ) {
            add_index_long(return_value, template[i].type, *((CK_ULONG*)(template[i].pValue)));
            efree(template[i].pValue);
            continue;
        }

        if (template[i].type == CKA_TOKEN
         || template[i].type == CKA_PRIVATE
         || template[i].type == CKA_MODIFIABLE
         || template[i].type == CKA_COPYABLE
         || template[i].type == CKA_DESTROYABLE
         || template[i].type == CKA_SENSITIVE
         || template[i].type == CKA_EXTRACTABLE
         || template[i].type == CKA_LOCAL
         || template[i].type == CKA_NEVER_EXTRACTABLE
         || template[i].type == CKA_ALWAYS_SENSITIVE
         || template[i].type == CKA_ENCRYPT
         || template[i].type == CKA_DECRYPT
         || template[i].type == CKA_WRAP
         || template[i].type == CKA_UNWRAP
         || template[i].type == CKA_SIGN
         || template[i].type == CKA_SIGN_RECOVER
         || template[i].type == CKA_VERIFY
         || template[i].type == CKA_VERIFY_RECOVER
         || template[i].type == CKA_DERIVE
         || template[i].type == CKA_TRUSTED
         || template[i].type == CKA_ALWAYS_AUTHENTICATE
         || template[i].type == CKA_WRAP_WITH_TRUSTED
         || template[i].type == CKA_SECONDARY_AUTH
         || template[i].type == CKA_OTP_USER_FRIENDLY_MODE
         || template[i].type == CKA_RESET_ON_INIT
         || template[i].type == CKA_HAS_RESET
         || template[i].type == CKA_COLOR
         || template[i].type == CKA_X2RATCHET_BOBS1STMSG
         || template[i].type == CKA_X2RATCHET_ISALICE
        ) {
            add_index_bool(return_value, template[i].type, *((CK_BBOOL*)(template[i].pValue)));
            efree(template[i].pValue);
            continue;
        }

        if (template[i].type == CKA_WRAP_TEMPLATE
         || template[i].type == CKA_UNWRAP_TEMPLATE
         || template[i].type == CKA_DERIVE_TEMPLATE
        ) {
            general_error("Unable to get attribute value", "Attribute type not implemented");
            efree(template[i].pValue);
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
    GC_DELREF(&obj->session->std);
}

static zend_function_entry object_class_functions[] = {
    PHP_ME(Object, getAttributeValue, arginfo_getAttributeValue, ZEND_ACC_PUBLIC)
    PHP_ME(Object, getSize, arginfo_getSize, ZEND_ACC_PUBLIC)
    PHP_FE_END
};


DEFINE_MAGIC_FUNCS(pkcs11_object, object, P11Object)
