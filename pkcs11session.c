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
#include "standard/php_string.h"

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
    ZEND_ARG_OBJ_INFO(0, mechanism, Pkcs11\\Mechanism, 0)
    ZEND_ARG_TYPE_INFO(0, template, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_generateKeyPair, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, mechanism, Pkcs11\\Mechanism, 0)
    ZEND_ARG_TYPE_INFO(0, pkTemplate, IS_ARRAY, 0)
    ZEND_ARG_TYPE_INFO(0, skTemplate, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_digest, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, mechanism, Pkcs11\\Mechanism, 0)
    ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_initializeDigest, 0, 0, 1)
    ZEND_ARG_OBJ_INFO(0, mechanism, Pkcs11\\Mechanism, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_findObjects, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, template, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_createObject, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, template, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_copyObject, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, object, Pkcs11\\P11Object, 0)
    ZEND_ARG_TYPE_INFO(0, template, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_destroyObject, 0, 0, 1)
    ZEND_ARG_OBJ_INFO(0, object, Pkcs11\\P11Object, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo___debugInfo, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_seedRandom, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, seed, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_generateRandom, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, length, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_openUri, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, uri, IS_STRING, 0)
ZEND_END_ARG_INFO()

CK_RV php_C_GetSessionInfo(const pkcs11_session_object * const objval, zval *retval) {
    CK_SESSION_INFO sessionInfo = {};
    CK_RV rv;

    rv = objval->pkcs11->functionList->C_GetSessionInfo(objval->session, &sessionInfo);
    if (rv != CKR_OK)
        return rv;

    array_init(retval);

    add_assoc_long(retval, "slotID", sessionInfo.slotID);
    add_assoc_long(retval, "state", sessionInfo.state);
    add_assoc_long(retval, "flags", sessionInfo.flags);
    add_assoc_long(retval, "ulDeviceError", sessionInfo.ulDeviceError);

    return rv;
}

PHP_METHOD(Session, getInfo) {

    CK_RV rv;

    ZEND_PARSE_PARAMETERS_NONE();

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);
    rv = php_C_GetSessionInfo(objval, return_value);

    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to get session info");
        return;
    }
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

    ZEND_PARSE_PARAMETERS_NONE();

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);
    rv = objval->pkcs11->functionList->C_Logout(objval->session);
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to logout");
        return;
    }
}

CK_RV php_C_SeedRandom(const pkcs11_session_object * const objval, zend_string *php_pSeed) {
    CK_BYTE_PTR pSeed = (CK_BYTE_PTR)ZSTR_VAL(php_pSeed);
    CK_ULONG ulSeedLen = (CK_ULONG)ZSTR_LEN(php_pSeed);
    CK_RV rv;

    rv = objval->pkcs11->functionList->C_SeedRandom(objval->session, pSeed, ulSeedLen);
    if (rv != CKR_OK)
        return rv;

    return rv;
}

PHP_METHOD(Session, seedRandom) {

    CK_RV rv;
    zend_string *seed;

    ZEND_PARSE_PARAMETERS_START(1,1)
        Z_PARAM_STR(seed)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);
    rv = php_C_SeedRandom(objval, seed);

    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to seed random data");
        return;
    }
}

CK_RV php_C_GenerateRandom(const pkcs11_session_object * const objval, zend_long php_RandomLen, zval *retval) {
    CK_BYTE_PTR pRandomData;
    CK_ULONG ulRandomLen = (CK_ULONG)php_RandomLen;
    CK_RV rv;

    if (ulRandomLen < 1)
        return CKR_ARGUMENTS_BAD;

    pRandomData = (CK_BYTE_PTR)ecalloc(sizeof(*pRandomData), ulRandomLen);

    rv = objval->pkcs11->functionList->C_GenerateRandom(objval->session, pRandomData, ulRandomLen);
    if (rv != CKR_OK)
        return rv;

    ZVAL_STRINGL(retval, (char *)pRandomData, ulRandomLen);
    efree(pRandomData);

    return rv;
}

PHP_METHOD(Session, generateRandom) {

    CK_RV rv;
    zend_long length;

    ZEND_PARSE_PARAMETERS_START(1,1)
        Z_PARAM_LONG(length)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);
    rv = php_C_GenerateRandom(objval, length, return_value);

    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to generate random data");
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

CK_RV php_C_GenerateKey(pkcs11_session_object *objval, zval *mechanism, HashTable *template, zval *retval) {
    CK_RV rv;

    CK_OBJECT_HANDLE hKey;
    pkcs11_mechanism_object *mechanismObjval = Z_PKCS11_MECHANISM_P(mechanism);

    int templateItemCount;
    CK_ATTRIBUTE_PTR templateObj;
    parseTemplate(&template, &templateObj, &templateItemCount);

    rv = objval->pkcs11->functionList->C_GenerateKey(
        objval->session,
        &mechanismObjval->mechanism,
        templateObj, templateItemCount, &hKey
    );
    freeTemplate(templateObj);

    if (rv != CKR_OK) {
        return rv;
    }

    pkcs11_key_object* key_obj;

    object_init_ex(retval, ce_Pkcs11_Key);
    key_obj = Z_PKCS11_KEY_P(retval);
    key_obj->session = objval;
    key_obj->key = hKey;
    GC_ADDREF(&objval->std);

    return rv;
}

PHP_METHOD(Session, generateKey) {

    CK_RV rv;
    zval *mechanism;
    HashTable *template;

    ZEND_PARSE_PARAMETERS_START(2,2)
        Z_PARAM_ZVAL(mechanism)
        Z_PARAM_ARRAY_HT(template)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);
    rv = php_C_GenerateKey(objval, mechanism, template, return_value);

    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to generate key");
        return;
    }
}


CK_RV php_C_GenerateKeyPair(pkcs11_session_object *objval, zval *mechanism, HashTable *pkTemplate, HashTable *skTemplate, zval *retvalPk, zval *retvalSk) {
    CK_RV rv;

    CK_OBJECT_HANDLE pKey, sKey;
    pkcs11_mechanism_object *mechanismObjval = Z_PKCS11_MECHANISM_P(mechanism);

    int skTemplateItemCount;
    CK_ATTRIBUTE_PTR skTemplateObj;
    parseTemplate(&skTemplate, &skTemplateObj, &skTemplateItemCount);

    int pkTemplateItemCount;
    CK_ATTRIBUTE_PTR pkTemplateObj;
    parseTemplate(&pkTemplate, &pkTemplateObj, &pkTemplateItemCount);

    rv = objval->pkcs11->functionList->C_GenerateKeyPair(
        objval->session,
        &mechanismObjval->mechanism,
        pkTemplateObj, pkTemplateItemCount,
        skTemplateObj, skTemplateItemCount,
        &pKey, &sKey
    );
    freeTemplate(skTemplateObj);
    freeTemplate(pkTemplateObj);

    if (rv != CKR_OK) {
        return rv;
    }

    pkcs11_key_object* skey_obj;
    object_init_ex(retvalSk, ce_Pkcs11_Key);
    skey_obj = Z_PKCS11_KEY_P(retvalSk);
    skey_obj->session = objval;
    skey_obj->key = sKey;
    GC_ADDREF(&objval->std);

    pkcs11_key_object* pkey_obj;
    object_init_ex(retvalPk, ce_Pkcs11_Key);
    pkey_obj = Z_PKCS11_KEY_P(retvalPk);
    pkey_obj->session = objval;
    pkey_obj->key = pKey;
    GC_ADDREF(&objval->std);

    return rv;
}

PHP_METHOD(Session, generateKeyPair) {

    CK_RV rv;
    zval *mechanism;
    HashTable *pkTemplate;
    HashTable *skTemplate;

    ZEND_PARSE_PARAMETERS_START(3,3)
        Z_PARAM_ZVAL(mechanism)
        Z_PARAM_ARRAY_HT(pkTemplate)
        Z_PARAM_ARRAY_HT(skTemplate)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);

    zval zpkeyobj;
    zval zskeyobj;

    rv = php_C_GenerateKeyPair(objval, mechanism, pkTemplate, skTemplate, &zpkeyobj, &zskeyobj);

    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to generate key pair");
        return ;
    }

    object_init_ex(return_value, ce_Pkcs11_KeyPair);
    add_property_zval(return_value, "pkey", &zpkeyobj);
    add_property_zval(return_value, "skey", &zskeyobj);

    pkcs11_key_object* skey_obj = Z_PKCS11_KEY_P(&zskeyobj);
    pkcs11_key_object* pkey_obj = Z_PKCS11_KEY_P(&zpkeyobj);

    pkcs11_keypair_object* keypair_obj;
    keypair_obj = Z_PKCS11_KEYPAIR_P(return_value);
    keypair_obj->pkey = pkey_obj;
    keypair_obj->skey = skey_obj;
}

PHP_METHOD(Session, digest) {

    CK_RV rv;
    zval *mechanism;
    zend_string *data;

    ZEND_PARSE_PARAMETERS_START(2,2)
        Z_PARAM_ZVAL(mechanism)
        Z_PARAM_STR(data)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_mechanism_object *mechanismObjval = Z_PKCS11_MECHANISM_P(mechanism);

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);
    rv = objval->pkcs11->functionList->C_DigestInit(
        objval->session,
        &mechanismObjval->mechanism
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to digest");
        return;
    }

    CK_ULONG digestLen;
    rv = objval->pkcs11->functionList->C_Digest(
        objval->session,
        ZSTR_VAL(data),
        ZSTR_LEN(data),
        NULL_PTR,
        &digestLen
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to digest");
        return;
    }

    CK_BYTE_PTR digest = ecalloc(digestLen, sizeof(CK_BYTE));
    rv = objval->pkcs11->functionList->C_Digest(
        objval->session,
        ZSTR_VAL(data),
        ZSTR_LEN(data),
        digest,
        &digestLen
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to digest");
        return;
    }

    zend_string *returnval;
    returnval = zend_string_alloc(digestLen, 0);
    memcpy(
        ZSTR_VAL(returnval),
        digest,
        digestLen
    );
    efree(digest);

    RETURN_STR(returnval);
}


PHP_METHOD(Session, initializeDigest) {

    CK_RV rv;
    zval *mechanism;

    ZEND_PARSE_PARAMETERS_START(1,1)
        Z_PARAM_ZVAL(mechanism)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_mechanism_object *mechanismObjval = Z_PKCS11_MECHANISM_P(mechanism);

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);
    rv = objval->pkcs11->functionList->C_DigestInit(
        objval->session,
        &mechanismObjval->mechanism
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to initialize digest");
        return;
    }

    pkcs11_digestcontext_object* context_obj;

    object_init_ex(return_value, ce_Pkcs11_DigestContext);
    context_obj = Z_PKCS11_DIGESTCONTEXT_P(return_value);
    context_obj->session = objval;
    GC_ADDREF(&objval->std);
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

    array_init(return_value);
    rv = php_C_FindObjects(objval, templateObj, templateItemCount, return_value);
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to find object");
    }

    freeTemplate(templateObj);
}

CK_RV php_C_CreateObject(pkcs11_session_object *objval, HashTable *template, zval *retval) {
    CK_RV rv;

    CK_OBJECT_HANDLE hObject;

    int templateItemCount;
    CK_ATTRIBUTE_PTR templateObj;
    parseTemplate(&template, &templateObj, &templateItemCount);


    rv = objval->pkcs11->functionList->C_CreateObject(
        objval->session,
        templateObj, templateItemCount, &hObject
    );
    freeTemplate(templateObj);

    if (rv != CKR_OK) {
        return rv;
    }

    CK_ULONG classId;
    getObjectClass(objval, &hObject, &classId);

    if (classId == 2 || classId == 3 || classId == 4 || classId == 8) {
        pkcs11_key_object* key_obj;
        object_init_ex(retval, ce_Pkcs11_Key);
        key_obj = Z_PKCS11_KEY_P(retval);
        key_obj->session = objval;
        key_obj->key = hObject;
        GC_ADDREF(&objval->std);
        return rv;
    }

    pkcs11_object_object* object_obj;

    object_init_ex(retval, ce_Pkcs11_P11Object);
    object_obj = Z_PKCS11_OBJECT_P(retval);
    object_obj->session = objval;
    object_obj->object = hObject;
    GC_ADDREF(&objval->std);

    return rv;
}
PHP_METHOD(Session, createObject) {

    CK_RV rv;
    HashTable *template;

    ZEND_PARSE_PARAMETERS_START(1,1)
        Z_PARAM_ARRAY_HT(template)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);

    rv = php_C_CreateObject(objval, template, return_value);

    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to create object");
        return;
    }
}

CK_RV php_C_CopyObject(pkcs11_session_object *objval, zval *objectOrig, HashTable *template, zval *retval) {
    CK_RV rv;

    CK_OBJECT_HANDLE hObject;

    int templateItemCount;
    CK_ATTRIBUTE_PTR templateObj;
    parseTemplate(&template, &templateObj, &templateItemCount);


    pkcs11_object_object *originalval = Z_PKCS11_OBJECT_P(objectOrig);
    rv = objval->pkcs11->functionList->C_CopyObject(
        objval->session,
        originalval->object, templateObj, templateItemCount, &hObject
    );
    freeTemplate(templateObj);

    if (rv != CKR_OK) {
        return rv;
    }

    CK_ULONG classId;
    getObjectClass(objval, &hObject, &classId);

    if (classId == 2 || classId == 3 || classId == 4 || classId == 8) {
        pkcs11_key_object* key_obj;
        object_init_ex(retval, ce_Pkcs11_Key);
        key_obj = Z_PKCS11_KEY_P(retval);
        key_obj->session = objval;
        key_obj->key = hObject;
        GC_ADDREF(&objval->std);
        return rv;
    }

    pkcs11_object_object* object_obj;

    object_init_ex(retval, ce_Pkcs11_P11Object);
    object_obj = Z_PKCS11_OBJECT_P(retval);
    object_obj->session = objval;
    object_obj->object = hObject;
    GC_ADDREF(&objval->std);

    return rv;
}
PHP_METHOD(Session, copyObject) {

    CK_RV rv;
    zval *object = NULL;
    HashTable *template;

    ZEND_PARSE_PARAMETERS_START(2,2)
        Z_PARAM_ZVAL(object)
        Z_PARAM_ARRAY_HT(template)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);
    rv = php_C_CopyObject(objval, object, template, return_value);

    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to copy object");
        return;
    }
}

CK_RV php_C_DestroyObject(pkcs11_session_object *objval, zval *object) {
    CK_RV rv;

    pkcs11_object_object *p11objval = Z_PKCS11_OBJECT_P(object);
    rv = objval->pkcs11->functionList->C_DestroyObject(
        objval->session,
        p11objval->object
    );

    return rv;
}
PHP_METHOD(Session, destroyObject) {

    CK_RV rv;
    zval *object = NULL;

    ZEND_PARSE_PARAMETERS_START(1,1)
        Z_PARAM_ZVAL(object)
    ZEND_PARSE_PARAMETERS_END();

    CK_OBJECT_HANDLE hObject;

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);
    rv = php_C_DestroyObject(objval, object);

    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to destroy object");
        return;
    }
}

PHP_METHOD(Session, __debugInfo) {
    ZEND_PARSE_PARAMETERS_NONE();

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);

    array_init(return_value);
    add_assoc_long(return_value, "hSession", objval->session);
    add_assoc_long(return_value, "slotID", objval->slotID);
    /* TODO: add $module objval->std */
}

void pkcs11_session_shutdown(pkcs11_session_object *obj) {
    // called before the pkcs11_session_object is freed
    // TBC: is it called before pkcs11_shutdown() ? It has to.
    if (obj->pkcs11->functionList != NULL) {
        obj->pkcs11->functionList->C_CloseSession(obj->session);
    }

    GC_DELREF(&obj->pkcs11->std);
}

PHP_METHOD(Session, openUri) {

    CK_RV rv;
    zend_long limit = ZEND_LONG_MAX;

    zval uri_array;
    zval uri_data_array;
    zend_string *uri;
    zend_string *uri_data;

    zend_string *uriDelim        = zend_string_init(":", strlen(":"), 0);
    zend_string *attributesDelim = zend_string_init(";", strlen(";"), 0);
    zend_string *keyValueDelim   = zend_string_init("=", strlen("="), 0);


    ZEND_PARSE_PARAMETERS_START(1,1)
        Z_PARAM_STR(uri)
    ZEND_PARSE_PARAMETERS_END();

    array_init(&uri_array);
    array_init(&uri_data_array);

    php_explode(uriDelim, uri, &uri_array, limit);
    zend_long cnt = zend_array_count(Z_ARRVAL_P(&uri_array));

    if (cnt != 2 && strcmp(ZSTR_VAL(Z_STR_P(zend_hash_index_find(Z_ARR(uri_array), 0))), "pkcs11")) {
        pkcs11_error(CKR_GENERAL_ERROR, "Invalid URI format");
        return;
    }

    uri_data = Z_STR_P(zend_hash_index_find(Z_ARR(uri_array), 1));
    php_explode(attributesDelim, uri_data, &uri_data_array, limit);

    char *attrId = NULL;
    char *attrObject = NULL;
    CK_OBJECT_CLASS attrType = NULL_PTR;

    char *tableKey = NULL;
    char *tableValue = NULL;
    int nbAttributes = 0;
    for (int i = 0; i < zend_array_count(Z_ARRVAL_P(&uri_data_array)); i++) {
        // If finish with an ; dont return an error
        zend_string *testVal = Z_STR_P(zend_hash_index_find(Z_ARR(uri_data_array), i));
        if (!testVal || ZSTR_LEN(testVal) <= 0)
            continue;

        zval key_values_array;
        array_init(&key_values_array);
        php_explode(keyValueDelim, testVal, &key_values_array, limit);

        if (zend_array_count(Z_ARRVAL_P(&key_values_array)) != 2) {
            general_error("Could not parse PKCS11 URI", "Invalid URI format");
            return;
        }

        tableKey = ZSTR_VAL(Z_STR_P(zend_hash_index_find(Z_ARR(key_values_array), 0)));
        tableValue = ZSTR_VAL(Z_STR_P(zend_hash_index_find(Z_ARR(key_values_array), 1)));

        if (strcmp(tableKey, "object") == 0) {
            attrObject = tableValue;
            nbAttributes++;
        }
        if (strcmp(tableKey, "id") == 0) {
            attrId = tableValue;
            nbAttributes++;
        }
        if (strcmp(tableKey, "type") == 0) {
            if (strcmp(tableValue, "secret-key") == 0)
                attrType = CKO_SECRET_KEY;
            else if (strcmp(tableValue, "public") == 0)
                attrType = CKO_PUBLIC_KEY;
            else if (strcmp(tableValue, "private") == 0)
                attrType = CKO_PRIVATE_KEY;
            else if (strcmp(tableValue, "cert") == 0)
                attrType = CKO_CERTIFICATE;
            else if (strcmp(tableValue, "data") == 0)
                attrType = CKO_DATA;
            else {
                general_error("Could not parse PKCS11 URI", "Invalid type attribute value");
                return;
            }
            nbAttributes++;
        }
	}
    CK_ATTRIBUTE *tmpl = ecalloc(nbAttributes, sizeof(CK_ATTRIBUTE));


    int i = 0;
    if (attrType != NULL_PTR) {
        (tmpl)[i] = (CK_ATTRIBUTE){CKA_CLASS, &attrType, sizeof(attrType)};
        i++;
    }
    if (attrObject != NULL_PTR) {
        (tmpl)[i] = (CK_ATTRIBUTE){CKA_LABEL, attrObject, strlen(attrObject)};
        i++;
    }
    if (attrId != NULL_PTR) {
        (tmpl)[i] = (CK_ATTRIBUTE){CKA_ID, attrId, strlen(attrId)};
        i++;
    }

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);

    array_init(return_value);
    rv = php_C_FindObjects(objval, tmpl, nbAttributes, return_value);
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to find object");
    }

    freeTemplate(tmpl);
}

CK_RV php_C_FindObjects(pkcs11_session_object *objval,  CK_ATTRIBUTE *tmpl, int nbAttributes, zval *return_value) {
    CK_RV rv;

    rv = objval->pkcs11->functionList->C_FindObjectsInit(objval->session, tmpl, nbAttributes);
    if (rv != CKR_OK) {
        return rv;
    }

    CK_OBJECT_HANDLE hObject;
    CK_ULONG ulObjectCount;
    while (1) {
        rv = objval->pkcs11->functionList->C_FindObjects(objval->session, &hObject, 1, &ulObjectCount);
        if (rv != CKR_OK || ulObjectCount == 0) {
            break;
        }

        CK_ULONG classId;
        getObjectClass(objval, &hObject, &classId);

        if (classId == 2 || classId == 3 || classId == 4 || classId == 8) {
            zval zkeyobj;
            pkcs11_key_object* key_obj;
            object_init_ex(&zkeyobj, ce_Pkcs11_Key);
            key_obj = Z_PKCS11_KEY_P(&zkeyobj);
            key_obj->session = objval;
            key_obj->key = hObject;
            GC_ADDREF(&objval->std);
            zend_hash_next_index_insert(Z_ARRVAL_P(return_value), &zkeyobj);
            continue;
        }

        zval zp11objectobj;
        pkcs11_object_object* object_obj;
        object_init_ex(&zp11objectobj, ce_Pkcs11_P11Object);
        object_obj = Z_PKCS11_OBJECT_P(&zp11objectobj);
        object_obj->session = objval;
        object_obj->object = hObject;
        GC_ADDREF(&objval->std);
        zend_hash_next_index_insert(Z_ARRVAL_P(return_value), &zp11objectobj);
    }

    rv = objval->pkcs11->functionList->C_FindObjectsFinal(objval->session);

    return rv;
}



static zend_function_entry session_class_functions[] = {
    PHP_ME(Session, login,            arginfo_login,            ZEND_ACC_PUBLIC)
    PHP_ME(Session, getInfo,          arginfo_getInfo,          ZEND_ACC_PUBLIC)
    PHP_ME(Session, logout,           arginfo_logout,           ZEND_ACC_PUBLIC)
    PHP_ME(Session, initPin,          arginfo_initPin,          ZEND_ACC_PUBLIC)
    PHP_ME(Session, setPin,           arginfo_setPin,           ZEND_ACC_PUBLIC)
    PHP_ME(Session, findObjects,      arginfo_findObjects,      ZEND_ACC_PUBLIC)
    PHP_ME(Session, createObject,     arginfo_createObject,     ZEND_ACC_PUBLIC)
    PHP_ME(Session, copyObject,       arginfo_copyObject,       ZEND_ACC_PUBLIC)
    PHP_ME(Session, destroyObject,    arginfo_destroyObject,    ZEND_ACC_PUBLIC)
    PHP_ME(Session, digest,           arginfo_digest,           ZEND_ACC_PUBLIC)
    PHP_ME(Session, initializeDigest, arginfo_initializeDigest, ZEND_ACC_PUBLIC)
    PHP_ME(Session, generateKey,      arginfo_generateKey,      ZEND_ACC_PUBLIC)
    PHP_ME(Session, generateKeyPair,  arginfo_generateKeyPair,  ZEND_ACC_PUBLIC)
    PHP_ME(Session, seedRandom,       arginfo_seedRandom,       ZEND_ACC_PUBLIC)
    PHP_ME(Session, generateRandom,   arginfo_generateRandom,   ZEND_ACC_PUBLIC)
    PHP_ME(Session, openUri,          arginfo_openUri,   ZEND_ACC_PUBLIC)

    PHP_ME(Session, __debugInfo,      arginfo___debugInfo,        ZEND_ACC_PUBLIC)

    PHP_FE_END
};


DEFINE_MAGIC_FUNCS(pkcs11_session, session, Session)
