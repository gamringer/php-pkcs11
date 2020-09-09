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

zend_class_entry *ce_Pkcs11_Module;
static zend_object_handlers pkcs11_handlers;


ZEND_BEGIN_ARG_INFO_EX(arginfo___construct, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, modulePath, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_getInfo, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_C_GetInfo, 0, 0, 1)
    ZEND_ARG_INFO(1, pInfo)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_getSlots, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_getSlotList, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_C_GetSlotList, 0, 0, 2)
    ZEND_ARG_INFO(0, tokenPresent)
    ZEND_ARG_INFO(1, pSlotList)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_getSlotInfo, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, slotId, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_C_GetSlotInfo, 0, 0, 2)
    ZEND_ARG_INFO(0, slotId)
    ZEND_ARG_INFO(1, pInfo)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_getTokenInfo, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, slotId, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_C_GetTokenInfo, 0, 0, 2)
    ZEND_ARG_INFO(0, slotId)
    ZEND_ARG_INFO(1, pInfo)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_getMechanismList, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, slotId, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_C_GetMechanismList, 0, 0, 2)
    ZEND_ARG_INFO(0, slotId)
    ZEND_ARG_INFO(1, pMechanismList)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_getMechanismInfo, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, slotId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, mechanismId, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_C_GetMechanismInfo, 0, 0, 3)
    ZEND_ARG_INFO(0, slotId)
    ZEND_ARG_INFO(0, type)
    ZEND_ARG_INFO(1, pInfo)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_initToken, 0, 0, 3)
    ZEND_ARG_TYPE_INFO(0, slotid, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, label, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, sopin, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_C_InitToken, 0, 0, 3)
    ZEND_ARG_TYPE_INFO(0, slotid, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, label, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, sopin, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_openSession, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, slotid, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
ZEND_END_ARG_INFO()


PHP_METHOD(Module, __construct) {
    char *module_path;
    size_t module_path_len;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_PATH(module_path, module_path_len)
    ZEND_PARSE_PARAMETERS_END();


    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);

    if (objval->initialised) {
        zend_throw_exception(zend_ce_exception, "Already initialised PKCS11 module", 0);
        return;
    }

    CK_RV rv;

    char* dlerror_str;
    objval->pkcs11module = dlopen(module_path, RTLD_NOW);

    dlerror_str = dlerror();
    if (dlerror_str != NULL) {
        general_error("Unable to initialise PKCS11 module", dlerror_str);
        return;
    }

    CK_C_GetFunctionList C_GetFunctionList = dlsym(objval->pkcs11module, "C_GetFunctionList");
    dlerror_str = dlerror();
    if (dlerror_str != NULL) {
        general_error("Unable to initialise PKCS11 module", dlerror_str);
        return;
    }

    rv = C_GetFunctionList(&objval->functionList);
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to retrieve function list");
        return;
    }

    rv = objval->functionList->C_Initialize(NULL);
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to initialise token");
        return;
    }

    objval->initialised = true;
}


CK_RV php_C_GetInfo(pkcs11_object *objval, zval *retval) {

    CK_RV rv;
    CK_INFO info;

    rv = objval->functionList->C_GetInfo(&info);
    if (rv != CKR_OK) {
        return rv;
    }

    zval cryptokiversion;
    array_init(&cryptokiversion);
    add_assoc_long(&cryptokiversion, "major", info.cryptokiVersion.major);
    add_assoc_long(&cryptokiversion, "minor", info.cryptokiVersion.minor);

    zval libversion;
    array_init(&libversion);
    add_assoc_long(&libversion, "major", info.libraryVersion.major);
    add_assoc_long(&libversion, "minor", info.libraryVersion.minor);

    array_init(retval);
    add_assoc_zval(retval, "cryptokiVersion", &cryptokiversion);
    add_assoc_stringl(retval, "manufacturerID", info.manufacturerID, sizeof(info.manufacturerID));
    add_assoc_stringl(retval, "libraryDescription", info.libraryDescription, sizeof(info.libraryDescription));
    add_assoc_zval(retval, "libraryVersion", &libversion);

    return rv;
}

PHP_METHOD(Module, getInfo) {
    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);

    if (!objval->initialised) {
        zend_throw_exception(zend_ce_exception, "Uninitialised PKCS11 module", 0);
        return;
    }

    CK_RV rv = php_C_GetInfo(objval, return_value);
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to get information from token");
    }
}

PHP_METHOD(Module, C_GetInfo) {
    CK_RV rv;
    zval *pInfo;
    zval retval;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(pInfo)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);

    if (!objval->initialised) {
        zend_throw_exception(zend_ce_exception, "Uninitialised PKCS11 module", 0);
        return;
    }

    rv = php_C_GetInfo(objval, &retval);

    ZEND_TRY_ASSIGN_REF_VALUE(pInfo, &retval);

    RETURN_LONG(rv);
}

CK_RV php_C_GetSlotList(pkcs11_object *objval, zend_bool tokenPresent, zval *retval) {

    CK_RV rv;
    CK_ULONG ulSlotCount;
    CK_SLOT_ID_PTR pSlotList;

    rv = objval->functionList->C_GetSlotList((CK_BBOOL)tokenPresent, NULL_PTR, &ulSlotCount);
    if (rv != CKR_OK) {
        return rv;
    }

    pSlotList = (CK_SLOT_ID_PTR) ecalloc(ulSlotCount, sizeof(CK_SLOT_ID));
    rv = objval->functionList->C_GetSlotList((CK_BBOOL)tokenPresent, pSlotList, &ulSlotCount);
    if (rv != CKR_OK) {
        efree(pSlotList);
        return rv;
    }

    array_init(retval);
    for (CK_SLOT_ID i=0; i<ulSlotCount; i++) {
        add_next_index_long(retval, pSlotList[i]);
    }

    efree(pSlotList);

    return rv;
}

PHP_METHOD(Module, getSlots) {
    CK_RV rv;
    CK_ULONG ulSlotCount;
    CK_SLOT_ID_PTR pSlotList;
    CK_SLOT_INFO slotInfo;

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);

    if (!objval->initialised) {
        zend_throw_exception(zend_ce_exception, "Uninitialised PKCS11 module", 0);
        return;
    }

    rv = objval->functionList->C_GetSlotList(CK_FALSE, NULL_PTR, &ulSlotCount);
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to get slot list from token");
        return;
    }

    pSlotList = (CK_SLOT_ID_PTR) ecalloc(ulSlotCount, sizeof(CK_SLOT_ID));
    rv = objval->functionList->C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
    if (rv != CKR_OK) {
        efree(pSlotList);
        pkcs11_error(rv, "Unable to get slot list from token");
        return;
    }

    zval slotObj;
    array_init(return_value);
    for (CK_SLOT_ID i=0; i<ulSlotCount; i++) {
        rv = objval->functionList->C_GetSlotInfo(pSlotList[i], &slotInfo);
        if (rv != CKR_OK) {
            pkcs11_error(rv, "Unable to get slot info from token");
            return;
        }

        array_init(&slotObj);
        add_assoc_long(&slotObj, "id", pSlotList[i]);
        add_assoc_stringl(&slotObj, "slotDescription", slotInfo.slotDescription, sizeof(slotInfo.slotDescription));
        add_index_zval(return_value, pSlotList[i], &slotObj);
    }
    efree(pSlotList);
}

PHP_METHOD(Module, getSlotList) {

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);

    if (!objval->initialised) {
        zend_throw_exception(zend_ce_exception, "Uninitialised PKCS11 module", 0);
        return;
    }

    CK_RV rv = php_C_GetSlotList(objval, false, return_value);
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to get slot list from token");
    }
}

PHP_METHOD(Module, C_GetSlotList) {
    CK_RV rv;
    zend_bool tokenPresent;
    zval *pSlotList;
    zval retval;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_BOOL(tokenPresent)
        Z_PARAM_ZVAL(pSlotList)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);

    if (!objval->initialised) {
        zend_throw_exception(zend_ce_exception, "Uninitialised PKCS11 module", 0);
        return;
    }

    rv = php_C_GetSlotList(objval, tokenPresent, &retval);

    ZEND_TRY_ASSIGN_REF_VALUE(pSlotList, &retval);

    RETURN_LONG(rv);
}


CK_RV php_C_GetSlotInfo(pkcs11_object *objval, zend_long slotId, zval *retval) {

    CK_RV rv;
    CK_SLOT_INFO slotInfo;

    rv = objval->functionList->C_GetSlotInfo((CK_SLOT_ID)slotId, &slotInfo);
    if (rv != CKR_OK) {
        return rv;
    }

    array_init(retval);
    add_assoc_long(retval, "id", (CK_SLOT_ID)slotId);
    add_assoc_stringl(retval, "description", slotInfo.slotDescription, 64);
    add_assoc_stringl(retval, "manufacturerID", slotInfo.manufacturerID, sizeof(slotInfo.manufacturerID));
    add_assoc_long(retval, "flags", slotInfo.flags);

    zval hardwareVersion;
    array_init(&hardwareVersion);
    add_assoc_long(&hardwareVersion, "major", slotInfo.hardwareVersion.major);
    add_assoc_long(&hardwareVersion, "minor", slotInfo.hardwareVersion.minor);
    add_assoc_zval(retval, "hardwareVersion", &hardwareVersion);

    zval firmwareVersion;
    array_init(&firmwareVersion);
    add_assoc_long(&firmwareVersion, "major", slotInfo.firmwareVersion.major);
    add_assoc_long(&firmwareVersion, "minor", slotInfo.firmwareVersion.minor);
    add_assoc_zval(retval, "firmwareVersion", &firmwareVersion);

    return rv;
}

PHP_METHOD(Module, getSlotInfo) {

    zend_long slotId;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(slotId)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);

    if (!objval->initialised) {
        zend_throw_exception(zend_ce_exception, "Uninitialised PKCS11 module", 0);
        return;
    }


    CK_RV rv = php_C_GetSlotInfo(objval, slotId, return_value);
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to get slot info from token");
    }
}

PHP_METHOD(Module, C_GetSlotInfo) {
    CK_RV rv;
    zend_long slotId;
    zval *pInfo;
    zval retval;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_LONG(slotId)
        Z_PARAM_ZVAL(pInfo)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);

    if (!objval->initialised) {
        zend_throw_exception(zend_ce_exception, "Uninitialised PKCS11 module", 0);
        return;
    }

    rv = php_C_GetSlotInfo(objval, slotId, &retval);

    ZEND_TRY_ASSIGN_REF_VALUE(pInfo, &retval);

    RETURN_LONG(rv);
}


CK_RV php_C_GetTokenInfo(pkcs11_object *objval, CK_SLOT_ID slotId, zval *retval) {

    CK_RV rv;
    CK_TOKEN_INFO tokenInfo = {};

    rv = objval->functionList->C_GetTokenInfo((CK_SLOT_ID)slotId, &tokenInfo);
    if (rv != CKR_OK) {
        return rv;
    }

    array_init(retval);
    add_assoc_stringl(retval, "label", tokenInfo.label, sizeof(tokenInfo.label));
    add_assoc_stringl(retval, "manufacturerID", tokenInfo.manufacturerID, sizeof(tokenInfo.manufacturerID));
    add_assoc_stringl(retval, "model", tokenInfo.model, sizeof(tokenInfo.model));
    add_assoc_stringl(retval, "serialNumber", tokenInfo.serialNumber, sizeof(tokenInfo.serialNumber));

    add_assoc_long(retval, "flags", tokenInfo.flags);

    add_assoc_long(retval, "ulMaxSessionCount", tokenInfo.ulMaxSessionCount);
    add_assoc_long(retval, "ulSessionCount", tokenInfo.ulSessionCount);
    add_assoc_long(retval, "ulMaxRwSessionCount", tokenInfo.ulMaxRwSessionCount);
    add_assoc_long(retval, "ulRwSessionCount", tokenInfo.ulRwSessionCount);
    add_assoc_long(retval, "ulMaxPinLen", tokenInfo.ulMaxPinLen);
    add_assoc_long(retval, "ulMinPinLen", tokenInfo.ulMinPinLen);
    add_assoc_long(retval, "ulTotalPublicMemory", tokenInfo.ulTotalPublicMemory);
    add_assoc_long(retval, "ulFreePublicMemory", tokenInfo.ulFreePublicMemory);
    add_assoc_long(retval, "ulTotalPrivateMemory", tokenInfo.ulTotalPrivateMemory);
    add_assoc_long(retval, "ulFreePrivateMemory", tokenInfo.ulFreePrivateMemory);

    zval hardwareVersion;
    array_init(&hardwareVersion);
    add_assoc_long(&hardwareVersion, "major", tokenInfo.hardwareVersion.major);
    add_assoc_long(&hardwareVersion, "minor", tokenInfo.hardwareVersion.minor);
    add_assoc_zval(retval, "hardwareVersion", &hardwareVersion);

    zval firmwareVersion;
    array_init(&firmwareVersion);
    add_assoc_long(&firmwareVersion, "major", tokenInfo.firmwareVersion.major);
    add_assoc_long(&firmwareVersion, "minor", tokenInfo.firmwareVersion.minor);
    add_assoc_zval(retval, "firmwareVersion", &firmwareVersion);

    add_assoc_stringl(retval, "utcTime", tokenInfo.utcTime, sizeof(tokenInfo.utcTime));

    return rv;
}

PHP_METHOD(Module, getTokenInfo) {

    zend_long slotId;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(slotId)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);

    if (!objval->initialised) {
        zend_throw_exception(zend_ce_exception, "Uninitialised PKCS11 module", 0);
        return;
    }

    CK_RV rv = php_C_GetTokenInfo(objval, slotId, return_value);
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to get slot info from token");
    }
}

PHP_METHOD(Module, C_GetTokenInfo) {
    CK_RV rv;
    zend_long slotId;
    zval *pInfo;
    zval retval;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_LONG(slotId)
        Z_PARAM_ZVAL(pInfo)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);

    if (!objval->initialised) {
        zend_throw_exception(zend_ce_exception, "Uninitialised PKCS11 module", 0);
        return;
    }

    rv = php_C_GetTokenInfo(objval, slotId, &retval);

    ZEND_TRY_ASSIGN_REF_VALUE(pInfo, &retval);

    RETURN_LONG(rv);
}


CK_RV php_C_GetMechanismList(pkcs11_object *objval, zend_long slotId, zval *retval) {

    CK_RV rv;

    CK_ULONG ulMechanismCount;
    rv = objval->functionList->C_GetMechanismList((CK_SLOT_ID)slotId, NULL_PTR, &ulMechanismCount);
    if (rv != CKR_OK) {
        return rv;
    }

    CK_MECHANISM_TYPE_PTR pMechanismList = (CK_MECHANISM_TYPE_PTR) ecalloc(ulMechanismCount, sizeof(CK_MECHANISM_TYPE));
    rv = objval->functionList->C_GetMechanismList((CK_SLOT_ID)slotId, pMechanismList, &ulMechanismCount);
    if (rv != CKR_OK) {
        efree(pMechanismList);
        return rv;
    }

    CK_SLOT_ID i;
    array_init(retval);
    for (i=0; i<ulMechanismCount; i++) {
        add_next_index_long(retval, pMechanismList[i]);
    }
    efree(pMechanismList);

    return rv;
}

PHP_METHOD(Module, getMechanismList) {

    zend_long slotId;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(slotId)
    ZEND_PARSE_PARAMETERS_END();


    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);

    if (!objval->initialised) {
        zend_throw_exception(zend_ce_exception, "Uninitialised PKCS11 module", 0);
        return;
    }

    CK_RV rv = php_C_GetMechanismList(objval, slotId, return_value);
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to get mechanism list from token");
    }
}

PHP_METHOD(Module, C_GetMechanismList) {
    CK_RV rv;
    zend_long slotId;
    zval *pMechanismList;
    zval retval;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_LONG(slotId)
        Z_PARAM_ZVAL(pMechanismList)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);

    if (!objval->initialised) {
        zend_throw_exception(zend_ce_exception, "Uninitialised PKCS11 module", 0);
        return;
    }

    rv = php_C_GetMechanismList(objval, slotId, &retval);

    ZEND_TRY_ASSIGN_REF_VALUE(pMechanismList, &retval);

    RETURN_LONG(rv);
}


CK_RV php_C_GetMechanismInfo(pkcs11_object *objval, zend_long slotId, zend_long mechanismId, zval *retval) {

    CK_MECHANISM_INFO mechanismInfo = {};

    CK_RV rv = objval->functionList->C_GetMechanismInfo((CK_SLOT_ID)slotId, (CK_MECHANISM_TYPE)mechanismId, &mechanismInfo);
    if (rv != CKR_OK) {
        return rv;
    }

    array_init(retval);
    add_assoc_long(retval, "ulMinKeySize", mechanismInfo.ulMinKeySize);
    add_assoc_long(retval, "ulMaxKeySize", mechanismInfo.ulMaxKeySize);
    add_assoc_long(retval, "flags", mechanismInfo.flags);

    return rv;
}

PHP_METHOD(Module, getMechanismInfo) {

    zend_long slotId;
    zend_long mechanismId;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_LONG(slotId)
        Z_PARAM_LONG(mechanismId)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);

    if (!objval->initialised) {
        zend_throw_exception(zend_ce_exception, "Uninitialised PKCS11 module", 0);
        return;
    }

    CK_RV rv = php_C_GetMechanismInfo(objval, slotId, mechanismId, return_value);
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to get mechanism info");
    }
}

PHP_METHOD(Module, C_GetMechanismInfo) {
    CK_RV rv;
    zend_long slotId;
    zend_long type;
    zval *pInfo;
    zval retval;

    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_LONG(slotId)
        Z_PARAM_LONG(type)
        Z_PARAM_ZVAL(pInfo)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);

    if (!objval->initialised) {
        zend_throw_exception(zend_ce_exception, "Uninitialised PKCS11 module", 0);
        return;
    }

    rv = php_C_GetMechanismInfo(objval, slotId, type, &retval);

    ZEND_TRY_ASSIGN_REF_VALUE(pInfo, &retval);

    RETURN_LONG(rv);
}


CK_RV php_C_InitToken(pkcs11_object *objval, zend_long slotId, zend_string *label, zend_string *sopin, zval *retval) {

    CK_MECHANISM_INFO mechanismInfo;
    CK_RV rv = objval->functionList->C_InitToken((CK_SLOT_ID)slotId, (CK_UTF8CHAR_PTR)sopin, ZSTR_LEN(sopin), (CK_UTF8CHAR_PTR)label);
    if (rv != CKR_OK) {
        return rv;
    }

    return rv;
}

PHP_METHOD(Module, initToken) {
    zend_string    *label_str;
    zend_string    *sopin_str;
    zend_long      slotid;

    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_LONG(slotid)
        Z_PARAM_STR(label_str)
        Z_PARAM_STR(sopin_str)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);

    if (!objval->initialised) {
        zend_throw_exception(zend_ce_exception, "Uninitialised PKCS11 module", 0);
        return;
    }
    
    CK_RV rv = php_C_InitToken(objval, slotid, label_str, sopin_str, return_value);
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to initialise token");
    }
}

PHP_METHOD(Module, C_InitToken) {
    zend_string    *label_str;
    zend_string    *sopin_str;
    zend_long      slotid;

    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_LONG(slotid)
        Z_PARAM_STR(label_str)
        Z_PARAM_STR(sopin_str)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);

    if (!objval->initialised) {
        zend_throw_exception(zend_ce_exception, "Uninitialised PKCS11 module", 0);
        return;
    }

    CK_RV rv = php_C_InitToken(objval, slotid, label_str, sopin_str, return_value);

    RETURN_LONG(rv);
}


PHP_METHOD(Module, openSession) {
    CK_RV rv;

    zend_long      slotid;
    zend_long      flags;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_LONG(slotid)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(flags)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);

    if (!objval->initialised) {
        zend_throw_exception(zend_ce_exception, "Uninitialised PKCS11 module", 0);
        return;
    }

    pkcs11_session_object* session_obj;

    object_init_ex(return_value, ce_Pkcs11_Session);
    session_obj = Z_PKCS11_SESSION_P(return_value);
    session_obj->pkcs11 = objval;

    CK_SESSION_HANDLE phSession;
    rv = objval->functionList->C_OpenSession(slotid, CKF_SERIAL_SESSION | flags, NULL_PTR, NULL_PTR, &phSession);
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to open session");
        return;
    }
    session_obj->session = phSession;
}


ZEND_BEGIN_ARG_INFO_EX(arginfo_C_GetSessionInfo, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, session, IS_OBJECT, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Module, C_GetSessionInfo) {
    CK_RV rv;

    zval *session;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(session)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);
    pkcs11_session_object *sessionobjval = Z_PKCS11_SESSION_P(session);

    call_obj_func(&sessionobjval->std, "getInfo", return_value, 0, NULL);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_C_Login, 0, 0, 3)
    ZEND_ARG_TYPE_INFO(0, session, IS_OBJECT, 0)
    ZEND_ARG_TYPE_INFO(0, loginType, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, pin, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Module, C_Login) {
    CK_RV rv;

    zval *session;
    zval *userType;
    zval *pin;

    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_ZVAL(session)
        Z_PARAM_ZVAL(userType)
        Z_PARAM_ZVAL(pin)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);
    pkcs11_session_object *sessionobjval = Z_PKCS11_SESSION_P(session);

    zval params[] = {*userType, *pin};

    call_obj_func(&sessionobjval->std, "login", return_value, 2, params);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_C_Logout, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, session, IS_OBJECT, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Module, C_Logout) {
    CK_RV rv;

    zval *session;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(session)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);
    pkcs11_session_object *sessionobjval = Z_PKCS11_SESSION_P(session);

    call_obj_func(&sessionobjval->std, "logout", return_value, 0, NULL);
}


ZEND_BEGIN_ARG_INFO_EX(arginfo_C_SetPIN, 0, 0, 3)
    ZEND_ARG_TYPE_INFO(0, session, IS_OBJECT, 0)
    ZEND_ARG_TYPE_INFO(0, oldPin, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, newPin, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Module, C_SetPIN) {
    CK_RV rv;

    zval *session;
    zval *oldPin;
    zval *newPin;

    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_ZVAL(session)
        Z_PARAM_ZVAL(oldPin)
        Z_PARAM_ZVAL(newPin)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);
    pkcs11_session_object *sessionobjval = Z_PKCS11_SESSION_P(session);

    zval params[] = {*oldPin, *newPin};

    call_obj_func(&sessionobjval->std, "setPin", return_value, 2, params);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_C_GenerateKey, 0, 0, 3)
    ZEND_ARG_TYPE_INFO(0, session, IS_OBJECT, 0)
    ZEND_ARG_TYPE_INFO(0, mechanism, IS_OBJECT, 0)
    ZEND_ARG_TYPE_INFO(0, template, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Module, C_GenerateKey) {
    CK_RV rv;

    zval *session;
    zval *mechanism;
    zval *template;

    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_ZVAL(session)
        Z_PARAM_ZVAL(mechanism)
        Z_PARAM_ZVAL(template)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);
    pkcs11_session_object *sessionobjval = Z_PKCS11_SESSION_P(session);

    zval params[] = {*mechanism, *template};

    call_obj_func(&sessionobjval->std, "generateKey", return_value, 2, params);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_C_GenerateKeyPair, 0, 0, 4)
    ZEND_ARG_TYPE_INFO(0, session, IS_OBJECT, 0)
    ZEND_ARG_TYPE_INFO(0, mechanism, IS_OBJECT, 0)
    ZEND_ARG_TYPE_INFO(0, pkTemplate, IS_ARRAY, 0)
    ZEND_ARG_TYPE_INFO(0, skTemplate, IS_ARRAY, 0)
    ZEND_ARG_INFO(1, phPublicKey)
    ZEND_ARG_INFO(1, phPrivateKey)
ZEND_END_ARG_INFO()

PHP_METHOD(Module, C_GenerateKeyPair) {
    CK_RV rv;

    zval *session;
    zval *mechanism;
    zval *pkTemplate;
    zval *skTemplate;
    zval *phPublicKey;
    zval *phPrivateKey;

    ZEND_PARSE_PARAMETERS_START(6, 6)
        Z_PARAM_ZVAL(session)
        Z_PARAM_ZVAL(mechanism)
        Z_PARAM_ZVAL(pkTemplate)
        Z_PARAM_ZVAL(skTemplate)
        Z_PARAM_ZVAL(phPublicKey)
        Z_PARAM_ZVAL(phPrivateKey)
    ZEND_PARSE_PARAMETERS_END();
  
    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);
    pkcs11_session_object *sessionobjval = Z_PKCS11_SESSION_P(session);

    zval params[] = {*mechanism, *pkTemplate, *skTemplate};

    zval *retval = emalloc(sizeof(zval));
    call_obj_func(&sessionobjval->std, "generateKeyPair", retval, 3, params);

    zval *rvpr;
    zval *zpkey = zend_read_property(Z_PKCS11_KEYPAIR_P(retval)->std.ce, retval, "pkey", sizeof("pkey") - 1, 0, rvpr);
    zval *zskey = zend_read_property(Z_PKCS11_KEYPAIR_P(retval)->std.ce, retval, "skey", sizeof("skey") - 1, 0, rvpr);
    efree(retval);

    ZEND_TRY_ASSIGN_REF_VALUE(phPublicKey, zpkey);
    ZEND_TRY_ASSIGN_REF_VALUE(phPrivateKey, zskey);

}

ZEND_BEGIN_ARG_INFO_EX(arginfo_C_DigestInit, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, session, IS_OBJECT, 0)
    ZEND_ARG_TYPE_INFO(0, mechanism, IS_OBJECT, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Module, C_DigestInit) {
    CK_RV rv;

    zval *session;
    zval *mechanism;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_ZVAL(session)
        Z_PARAM_ZVAL(mechanism)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);
    pkcs11_session_object *sessionobjval = Z_PKCS11_SESSION_P(session);

    pkcs11_mechanism_object *mechanismObjval = Z_PKCS11_MECHANISM_P(mechanism);

    rv = sessionobjval->pkcs11->functionList->C_DigestInit(
        sessionobjval->session,
        &mechanismObjval->mechanism
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to initialize digest");
        return;
    }
}


ZEND_BEGIN_ARG_INFO_EX(arginfo_C_Digest, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, session, IS_OBJECT, 0)
    ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Module, C_Digest) {
    CK_RV rv;

    zval *session;
    zend_string *data;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_ZVAL(session)
        Z_PARAM_STR(data)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);
    pkcs11_session_object *sessionobjval = Z_PKCS11_SESSION_P(session);

    CK_ULONG digestLen;
    rv = sessionobjval->pkcs11->functionList->C_Digest(
        sessionobjval->session,
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
    rv = sessionobjval->pkcs11->functionList->C_Digest(
        sessionobjval->session,
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
    RETURN_STR(returnval);
 
    efree(digest);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_C_DigestUpdate, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, session, IS_OBJECT, 0)
    ZEND_ARG_TYPE_INFO(0, part, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Module, C_DigestUpdate) {
    CK_RV rv;

    zval *session;
    zend_string *part;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_ZVAL(session)
        Z_PARAM_STR(part)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);
    pkcs11_session_object *sessionobjval = Z_PKCS11_SESSION_P(session);

    rv = sessionobjval->pkcs11->functionList->C_DigestUpdate(
        sessionobjval->session,
        ZSTR_VAL(part),
        ZSTR_LEN(part)
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to update digest");
        return;
    }
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_C_DigestKey, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, session, IS_OBJECT, 0)
    ZEND_ARG_TYPE_INFO(0, key, IS_OBJECT, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Module, C_DigestKey) {
    CK_RV rv;

    zval *session;
    zval *key;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_ZVAL(session)
        Z_PARAM_ZVAL(key)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);
    pkcs11_session_object *sessionobjval = Z_PKCS11_SESSION_P(session);
    pkcs11_key_object *keyobjval = Z_PKCS11_KEY_P(key);

    rv = sessionobjval->pkcs11->functionList->C_DigestKey(
        sessionobjval->session,
        keyobjval->key
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to update digest");
        return;
    }
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_C_DigestFinal, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, session, IS_OBJECT, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Module, C_DigestFinal) {
    CK_RV rv;

    zval *session;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(session)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);
    pkcs11_session_object *sessionobjval = Z_PKCS11_SESSION_P(session);

    CK_ULONG digestLen;
    rv = sessionobjval->pkcs11->functionList->C_DigestFinal(
        sessionobjval->session,
        NULL_PTR,
        &digestLen
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to finalize digest");
        return;
    }

    CK_BYTE_PTR digest = ecalloc(digestLen, sizeof(CK_BYTE));
    rv = sessionobjval->pkcs11->functionList->C_DigestFinal(
        sessionobjval->session,
        digest,
        &digestLen
    );
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to finalize digest");
        return;
    }

    zend_string *returnval;
    returnval = zend_string_alloc(digestLen, 0);
    memcpy(
        ZSTR_VAL(returnval),
        digest,
        digestLen
    );
    RETURN_STR(returnval);
 
    efree(digest);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_C_CreateObject, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, session, IS_OBJECT, 0)
    ZEND_ARG_TYPE_INFO(0, template, IS_ARRAY, 0)
ZEND_END_ARG_INFO()


PHP_METHOD(Module, C_CreateObject) {
    CK_RV rv;

    zval *session;
    zval *template;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_ZVAL(session)
        Z_PARAM_ZVAL(template)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);
    pkcs11_session_object *sessionobjval = Z_PKCS11_SESSION_P(session);

    zval params[] = {*template};

    call_obj_func(&sessionobjval->std, "createObject", return_value, 1, params);
}


ZEND_BEGIN_ARG_INFO_EX(arginfo_C_FindObjects, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, session, IS_OBJECT, 0)
    ZEND_ARG_TYPE_INFO(0, template, IS_ARRAY, 0)
ZEND_END_ARG_INFO()


PHP_METHOD(Module, C_FindObjects) {
    CK_RV rv;

    zval *session;
    zval *template;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_ZVAL(session)
        Z_PARAM_ZVAL(template)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);
    pkcs11_session_object *sessionobjval = Z_PKCS11_SESSION_P(session);

    zval params[] = {*template};

    call_obj_func(&sessionobjval->std, "findObjects", return_value, 1, params);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_C_CopyObject, 0, 0, 3)
    ZEND_ARG_TYPE_INFO(0, session, IS_OBJECT, 0)
    ZEND_ARG_TYPE_INFO(0, object, IS_OBJECT, 0)
    ZEND_ARG_TYPE_INFO(0, template, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Module, C_CopyObject) {
    CK_RV rv;

    zval *session;
    zval *object;
    zval *template;

    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_ZVAL(session)
        Z_PARAM_ZVAL(object)
        Z_PARAM_ZVAL(template)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);
    pkcs11_session_object *sessionobjval = Z_PKCS11_SESSION_P(session);

    zval params[] = {*object, *template};

    call_obj_func(&sessionobjval->std, "copyObject", return_value, 2, params);
}


ZEND_BEGIN_ARG_INFO_EX(arginfo_C_DestroyObject, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, session, IS_OBJECT, 0)
    ZEND_ARG_INFO(0, object)
ZEND_END_ARG_INFO()

PHP_METHOD(Module, C_DestroyObject) {
    CK_RV rv;

    zval *session;
    zval *object;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_ZVAL(session)
        Z_PARAM_ZVAL(object)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);
    pkcs11_session_object *sessionobjval = Z_PKCS11_SESSION_P(session);

    zval params[] = {*object};

    call_obj_func(&sessionobjval->std, "destroyObject", return_value, 1, params);
}

void pkcs11_shutdown(pkcs11_object *obj) {
    // called before the pkcs11_object is freed
    if (obj->functionList != NULL) {
        obj->functionList->C_Finalize(NULL_PTR);
    }

    if (obj->pkcs11module != NULL) {
        dlclose(obj->pkcs11module);
    }
}


static zend_function_entry module_class_functions[] = {
    PHP_ME(Module, __construct,      arginfo___construct,      ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(Module, getInfo,          arginfo_getInfo,          ZEND_ACC_PUBLIC)
    PHP_ME(Module, getSlots,         arginfo_getSlots,         ZEND_ACC_PUBLIC)
    PHP_ME(Module, getSlotList,      arginfo_getSlotList,      ZEND_ACC_PUBLIC)
    PHP_ME(Module, getSlotInfo,      arginfo_getSlotInfo,      ZEND_ACC_PUBLIC)
    PHP_ME(Module, getTokenInfo,     arginfo_getTokenInfo,     ZEND_ACC_PUBLIC)
    PHP_ME(Module, getMechanismList, arginfo_getMechanismList, ZEND_ACC_PUBLIC)
    PHP_ME(Module, getMechanismInfo, arginfo_getMechanismInfo, ZEND_ACC_PUBLIC)
    PHP_ME(Module, initToken,        arginfo_initToken,        ZEND_ACC_PUBLIC)
    PHP_ME(Module, openSession,      arginfo_openSession,      ZEND_ACC_PUBLIC)

    PHP_ME(Module, C_GetInfo,          arginfo_C_GetInfo,          ZEND_ACC_PUBLIC)
    PHP_ME(Module, C_GetSlotList,      arginfo_C_GetSlotList,      ZEND_ACC_PUBLIC)
    PHP_ME(Module, C_GetSlotInfo,      arginfo_C_GetSlotInfo,      ZEND_ACC_PUBLIC)
    PHP_ME(Module, C_GetTokenInfo,     arginfo_C_GetTokenInfo,     ZEND_ACC_PUBLIC)
    PHP_ME(Module, C_GetMechanismList, arginfo_C_GetMechanismList, ZEND_ACC_PUBLIC)
    PHP_ME(Module, C_GetMechanismInfo, arginfo_C_GetMechanismInfo, ZEND_ACC_PUBLIC)
    PHP_ME(Module, C_InitToken,        arginfo_C_InitToken,        ZEND_ACC_PUBLIC)

    //PHP_MALIAS(Module, C_GetInfo,          getInfo,          arginfo_getInfo,          ZEND_ACC_PUBLIC)
    //PHP_MALIAS(Module, C_GetSlotList,      getSlotList,      arginfo_getSlotList,      ZEND_ACC_PUBLIC)
    //PHP_MALIAS(Module, C_GetSlotInfo,      getSlotInfo,      arginfo_getSlotInfo,      ZEND_ACC_PUBLIC)
    //PHP_MALIAS(Module, C_GetTokenInfo,     getTokenInfo,     arginfo_getTokenInfo,     ZEND_ACC_PUBLIC)
    //PHP_MALIAS(Module, C_GetMechanismList, getMechanismList, arginfo_getMechanismList, ZEND_ACC_PUBLIC)
    //PHP_MALIAS(Module, C_GetMechanismInfo, getMechanismInfo, arginfo_getMechanismInfo, ZEND_ACC_PUBLIC)
    //PHP_MALIAS(Module, C_InitToken,        initToken,        arginfo_initToken,        ZEND_ACC_PUBLIC)
    PHP_MALIAS(Module, C_OpenSession,      openSession,      arginfo_openSession,      ZEND_ACC_PUBLIC)

    PHP_ME(Module, C_GetSessionInfo,          arginfo_C_GetSessionInfo,          ZEND_ACC_PUBLIC)
    PHP_ME(Module, C_Login,                   arginfo_C_Login,                   ZEND_ACC_PUBLIC)
    PHP_ME(Module, C_Logout,                  arginfo_C_Logout,                  ZEND_ACC_PUBLIC)
    PHP_ME(Module, C_SetPIN,                  arginfo_C_SetPIN,                  ZEND_ACC_PUBLIC)
    PHP_ME(Module, C_GenerateKey,             arginfo_C_GenerateKey,             ZEND_ACC_PUBLIC)
    PHP_ME(Module, C_GenerateKeyPair,         arginfo_C_GenerateKeyPair,         ZEND_ACC_PUBLIC)
    PHP_ME(Module, C_DigestInit,              arginfo_C_DigestInit,              ZEND_ACC_PUBLIC)
    PHP_ME(Module, C_Digest,                  arginfo_C_Digest,                  ZEND_ACC_PUBLIC)
    PHP_ME(Module, C_DigestUpdate,            arginfo_C_DigestUpdate,            ZEND_ACC_PUBLIC)
    PHP_ME(Module, C_DigestKey,               arginfo_C_DigestKey,               ZEND_ACC_PUBLIC)
    PHP_ME(Module, C_DigestFinal,             arginfo_C_DigestFinal,             ZEND_ACC_PUBLIC)
    
    PHP_ME(Module, C_CreateObject,            arginfo_C_CreateObject,            ZEND_ACC_PUBLIC)
    PHP_ME(Module, C_FindObjects,             arginfo_C_FindObjects,             ZEND_ACC_PUBLIC)
    PHP_ME(Module, C_CopyObject,              arginfo_C_CopyObject,              ZEND_ACC_PUBLIC)
    PHP_ME(Module, C_DestroyObject,           arginfo_C_DestroyObject,           ZEND_ACC_PUBLIC)

    PHP_FE_END
};


DEFINE_MAGIC_FUNCS(pkcs11, module, Module)
