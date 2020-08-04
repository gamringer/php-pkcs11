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

zend_class_entry *ce_Pkcs11_Session;
static zend_object_handlers pkcs11_session_handlers;


ZEND_BEGIN_ARG_INFO_EX(arginfo_getInfo, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_login, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, loginType, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, pin, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_logout, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_initPin, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, pin, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_setPin, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, oldPin, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, newPin, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_generateKey, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, mechanismId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, template, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_generateKeyPair, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, mechanismId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, pkTemplate, IS_ARRAY, 0)
    ZEND_ARG_TYPE_INFO(0, skTemplate, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_findObjects, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, template, IS_ARRAY, 0)
ZEND_END_ARG_INFO()


PHP_METHOD(Session, getInfo) {

    CK_RV rv;
    CK_SESSION_INFO sessionInfo;

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);
    rv = objval->pkcs11->functionList->C_GetSessionInfo(objval->session, &sessionInfo);

    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to get session info");
        return;
    }

    array_init(return_value);
    add_assoc_long(return_value, "state", sessionInfo.state);
    add_assoc_long(return_value, "flags", sessionInfo.flags);
    add_assoc_long(return_value, "device_error", sessionInfo.ulDeviceError);
}


PHP_METHOD(Session, login) {

    CK_RV rv;
    zend_long userType;
    zend_string *pin;

    ZEND_PARSE_PARAMETERS_START(2,2)
        Z_PARAM_LONG(userType)
        Z_PARAM_STR(pin)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);
    rv = objval->pkcs11->functionList->C_Login(objval->session, userType, ZSTR_VAL(pin), ZSTR_LEN(pin));

    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to login");
        return;
    }
}


PHP_METHOD(Session, logout) {

    CK_RV rv;

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);
    rv = objval->pkcs11->functionList->C_Logout(objval->session);
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to logout");
        return;
    }
}


PHP_METHOD(Session, initPin) {

    CK_RV rv;
    zend_string *newPin;

    ZEND_PARSE_PARAMETERS_START(1,1)
        Z_PARAM_STR(newPin)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);
    rv = objval->pkcs11->functionList->C_InitPIN(objval->session, ZSTR_VAL(newPin), ZSTR_LEN(newPin));

    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to set pin");
        return;
    }
}


PHP_METHOD(Session, setPin) {

    CK_RV rv;
    zend_string *oldPin;
    zend_string *newPin;

    ZEND_PARSE_PARAMETERS_START(2,2)
        Z_PARAM_STR(oldPin)
        Z_PARAM_STR(newPin)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);
    rv = objval->pkcs11->functionList->C_SetPIN(
        objval->session,
        ZSTR_VAL(oldPin),
        ZSTR_LEN(oldPin),
        ZSTR_VAL(newPin),
        ZSTR_LEN(newPin)
    );

    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to set pin");
        return;
    }
}


PHP_METHOD(Session, generateKey) {

    CK_RV rv;
    zend_long mechanismId;
    HashTable *template;

    ZEND_PARSE_PARAMETERS_START(2,2)
        Z_PARAM_LONG(mechanismId)
        Z_PARAM_ARRAY_HT(template)
    ZEND_PARSE_PARAMETERS_END();

    CK_OBJECT_HANDLE hKey;
    CK_MECHANISM mechanism = {mechanismId, NULL_PTR, 0};

    int templateItemCount;
    CK_ATTRIBUTE_PTR templateObj;
    parseTemplate(&template, &templateObj, &templateItemCount);

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);
    rv = objval->pkcs11->functionList->C_GenerateKey(
        objval->session,
        &mechanism,
        templateObj, templateItemCount, &hKey
    );
    freeTemplate(templateObj);

    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to generate key");
        return;
    }

    pkcs11_key_object* key_obj;

    object_init_ex(return_value, ce_Pkcs11_Key);
    key_obj = Z_PKCS11_KEY_P(return_value);
    key_obj->session = objval;
    key_obj->key = hKey;
}


PHP_METHOD(Session, generateKeyPair) {

    CK_RV rv;
    zend_long mechanismId;
    HashTable *pkTemplate;
    HashTable *skTemplate;

    ZEND_PARSE_PARAMETERS_START(3,3)
        Z_PARAM_LONG(mechanismId)
        Z_PARAM_ARRAY_HT(pkTemplate)
        Z_PARAM_ARRAY_HT(skTemplate)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);

    CK_OBJECT_HANDLE pKey, sKey;

    CK_MECHANISM mechanism = {mechanismId, NULL_PTR, 0};
    int skTemplateItemCount;
    CK_ATTRIBUTE_PTR skTemplateObj;
    parseTemplate(&skTemplate, &skTemplateObj, &skTemplateItemCount);

    int pkTemplateItemCount;
    CK_ATTRIBUTE_PTR pkTemplateObj;
    parseTemplate(&pkTemplate, &pkTemplateObj, &pkTemplateItemCount);

    rv = objval->pkcs11->functionList->C_GenerateKeyPair(
        objval->session,
        &mechanism,
        pkTemplateObj, pkTemplateItemCount,
        skTemplateObj, skTemplateItemCount,
        &pKey, &sKey
    );
    freeTemplate(skTemplateObj);
    freeTemplate(pkTemplateObj);

    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to generate key pair");
        return;
    }

    zval zskeyobj;
    pkcs11_key_object* skey_obj;
    object_init_ex(&zskeyobj, ce_Pkcs11_Key);
    skey_obj = Z_PKCS11_KEY_P(&zskeyobj);
    skey_obj->session = objval;
    skey_obj->key = sKey;

    zval zpkeyobj;
    pkcs11_key_object* pkey_obj;
    object_init_ex(&zpkeyobj, ce_Pkcs11_Key);
    pkey_obj = Z_PKCS11_KEY_P(&zpkeyobj);
    pkey_obj->session = objval;
    pkey_obj->key = pKey;

    pkcs11_keypair_object* keypair_obj;

    object_init_ex(return_value, ce_Pkcs11_KeyPair);
    add_property_zval(return_value, "skey", &zskeyobj);
    add_property_zval(return_value, "pkey", &zpkeyobj);

    keypair_obj = Z_PKCS11_KEYPAIR_P(return_value);
    keypair_obj->pkey = pkey_obj;
    keypair_obj->skey = skey_obj;
}


PHP_METHOD(Session, findObjects) {

    CK_RV rv;
    HashTable *template;
    zval *templateValue;
    zend_ulong templateValueKey;

    ZEND_PARSE_PARAMETERS_START(1,1)
        Z_PARAM_ARRAY_HT(template)
    ZEND_PARSE_PARAMETERS_END();

    int templateItemCount;
    CK_ATTRIBUTE_PTR templateObj;
    parseTemplate(&template, &templateObj, &templateItemCount);

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);
    rv = objval->pkcs11->functionList->C_FindObjectsInit(objval->session, templateObj, templateItemCount);
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to find objects");
        freeTemplate(templateObj);
        return;
    }

    array_init(return_value);
    CK_OBJECT_HANDLE hObject;
    CK_ULONG ulObjectCount;
    while (1) {
        rv = objval->pkcs11->functionList->C_FindObjects(objval->session, &hObject, 1, &ulObjectCount);
        if (rv != CKR_OK || ulObjectCount == 0) {
            break;
        }

        zval zkeyobj;
        pkcs11_key_object* key_obj;
        object_init_ex(&zkeyobj, ce_Pkcs11_Key);
        key_obj = Z_PKCS11_KEY_P(&zkeyobj);
        key_obj->session = objval;
        key_obj->key = hObject;
        zend_hash_next_index_insert(Z_ARRVAL_P(return_value), &zkeyobj);
    }

    rv = objval->pkcs11->functionList->C_FindObjectsFinal(objval->session);

    freeTemplate(templateObj);
}


void pkcs11_session_shutdown(pkcs11_session_object *obj) {
    // called before the pkcs11_session_object is freed
    if (obj->pkcs11->functionList != NULL) {
        obj->pkcs11->functionList->C_CloseSession(obj->session);
    }
}

static zend_function_entry session_class_functions[] = {
    PHP_ME(Session, login,           arginfo_login,           ZEND_ACC_PUBLIC)
    PHP_ME(Session, getInfo,         arginfo_getInfo,         ZEND_ACC_PUBLIC)
    PHP_ME(Session, logout,          arginfo_logout,          ZEND_ACC_PUBLIC)
    PHP_ME(Session, initPin,         arginfo_initPin,         ZEND_ACC_PUBLIC)
    PHP_ME(Session, setPin,          arginfo_setPin,          ZEND_ACC_PUBLIC)
    PHP_ME(Session, findObjects,     arginfo_findObjects,     ZEND_ACC_PUBLIC)
    PHP_ME(Session, generateKey,     arginfo_generateKey,     ZEND_ACC_PUBLIC)
    PHP_ME(Session, generateKeyPair, arginfo_generateKeyPair, ZEND_ACC_PUBLIC)
    PHP_FE_END
};


DEFINE_MAGIC_FUNCS(pkcs11_session, session, Session)
