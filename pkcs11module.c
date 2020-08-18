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

ZEND_BEGIN_ARG_INFO_EX(arginfo_getSlots, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_getSlotList, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_getSlotInfo, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, slotId, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_getTokenInfo, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, slotId, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_getMechanismList, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, slotId, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_getMechanismInfo, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, slotId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, mechanismId, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_initToken, 0, 0, 3)
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


PHP_METHOD(Module, getInfo) {
    zend_string *retval;
    CK_RV rv;
    CK_INFO info;

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);

    if (!objval->initialised) {
        zend_throw_exception(zend_ce_exception, "Uninitialised PKCS11 module", 0);
        return;
    }

    rv = objval->functionList->C_GetInfo(&info);
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to get information from token");
        return;
    }

    zval cryptokiversion;
    array_init(&cryptokiversion);
    add_assoc_long(&cryptokiversion, "major", info.cryptokiVersion.major);
    add_assoc_long(&cryptokiversion, "minor", info.cryptokiVersion.minor);

    zval libversion;
    array_init(&libversion);
    add_assoc_long(&libversion, "major", info.libraryVersion.major);
    add_assoc_long(&libversion, "minor", info.libraryVersion.minor);

    array_init(return_value);
    add_assoc_zval(return_value, "version", &cryptokiversion);
    add_assoc_stringl(return_value, "manufacturer_id", info.manufacturerID, 32);
    add_assoc_stringl(return_value, "lib_description", info.libraryDescription, 32);
    add_assoc_zval(return_value, "lib_version", &libversion);
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

    uint i;
    zval slotObj;
    array_init(return_value);
    for (i=0; i<ulSlotCount; i++) {
        rv = objval->functionList->C_GetSlotInfo(pSlotList[i], &slotInfo);
        if (rv != CKR_OK) {
            pkcs11_error(rv, "Unable to get slot info from token");
            return;
        }

        array_init(&slotObj);
        add_assoc_long(&slotObj, "id", pSlotList[i]);
        add_assoc_stringl(&slotObj, "description", slotInfo.slotDescription, 64);
        add_index_zval(return_value, pSlotList[i], &slotObj);
    }
    efree(pSlotList);
}


PHP_METHOD(Module, getSlotList) {
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
        pkcs11_error(rv, "Unable to get slot list from token");
        return;
    }

    uint i;
    array_init(return_value);
    for (i=0; i<ulSlotCount; i++) {
        add_next_index_long(return_value, pSlotList[i]);
    }

    efree(pSlotList);
}


PHP_METHOD(Module, getSlotInfo) {

    zend_long slotId;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(slotId)
    ZEND_PARSE_PARAMETERS_END();

    CK_RV rv;
    CK_SLOT_INFO slotInfo;

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);

    if (!objval->initialised) {
        zend_throw_exception(zend_ce_exception, "Uninitialised PKCS11 module", 0);
        return;
    }

    rv = objval->functionList->C_GetSlotInfo(slotId, &slotInfo);
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to get slot info from token");
        return;
    }

    array_init(return_value);
    add_assoc_long(return_value, "id", slotId);
    add_assoc_stringl(return_value, "description", slotInfo.slotDescription, 64);
}


PHP_METHOD(Module, getTokenInfo) {

    zend_long slotId;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(slotId)
    ZEND_PARSE_PARAMETERS_END();

    CK_RV rv;
    CK_TOKEN_INFO tokenInfo;

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);

    if (!objval->initialised) {
        zend_throw_exception(zend_ce_exception, "Uninitialised PKCS11 module", 0);
        return;
    }

    rv = objval->functionList->C_GetTokenInfo(slotId, &tokenInfo);
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to get slot info from token");
        return;
    }

    array_init(return_value);
    add_assoc_stringl(return_value, "label", tokenInfo.label, 32);
    add_assoc_stringl(return_value, "manufacturerID", tokenInfo.manufacturerID, 32);
    add_assoc_stringl(return_value, "model", tokenInfo.model, 16);
    add_assoc_stringl(return_value, "serialNumber", tokenInfo.serialNumber, 16);

    add_assoc_long(return_value, "ulMaxSessionCount", tokenInfo.ulMaxSessionCount);
    add_assoc_long(return_value, "ulSessionCount", tokenInfo.ulSessionCount);
    add_assoc_long(return_value, "ulMaxRwSessionCount", tokenInfo.ulMaxRwSessionCount);
    add_assoc_long(return_value, "ulRwSessionCount", tokenInfo.ulRwSessionCount);
    add_assoc_long(return_value, "ulMaxPinLen", tokenInfo.ulMaxPinLen);
    add_assoc_long(return_value, "ulMinPinLen", tokenInfo.ulMinPinLen);
    add_assoc_long(return_value, "ulTotalPublicMemory", tokenInfo.ulTotalPublicMemory);
    add_assoc_long(return_value, "ulFreePublicMemory", tokenInfo.ulFreePublicMemory);
    add_assoc_long(return_value, "ulTotalPrivateMemory", tokenInfo.ulTotalPrivateMemory);
    add_assoc_long(return_value, "ulFreePrivateMemory", tokenInfo.ulFreePrivateMemory);

    zval hardwareVersion;
    array_init(&hardwareVersion);
    add_assoc_long(&hardwareVersion, "major", tokenInfo.hardwareVersion.major);
    add_assoc_long(&hardwareVersion, "minor", tokenInfo.hardwareVersion.minor);
    add_assoc_zval(return_value, "hardwareVersion", &hardwareVersion);

    zval firmwareVersion;
    array_init(&firmwareVersion);
    add_assoc_long(&firmwareVersion, "major", tokenInfo.firmwareVersion.major);
    add_assoc_long(&firmwareVersion, "minor", tokenInfo.firmwareVersion.minor);
    add_assoc_zval(return_value, "firmwareVersion", &firmwareVersion);

    add_assoc_stringl(return_value, "utcTime", tokenInfo.utcTime, 16);
}


PHP_METHOD(Module, getMechanismList) {

    zend_long slotId;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(slotId)
    ZEND_PARSE_PARAMETERS_END();

    CK_RV rv;
    CK_ULONG ulMechanismCount;
    CK_MECHANISM_TYPE_PTR pMechanismList;

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);

    if (!objval->initialised) {
        zend_throw_exception(zend_ce_exception, "Uninitialised PKCS11 module", 0);
        return;
    }

    rv = objval->functionList->C_GetMechanismList(slotId, NULL_PTR, &ulMechanismCount);
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to get mechanism list from token 1");
        return;
    }

    pMechanismList = (CK_MECHANISM_TYPE_PTR) ecalloc(ulMechanismCount, sizeof(CK_MECHANISM_TYPE));
    rv = objval->functionList->C_GetMechanismList(slotId, pMechanismList, &ulMechanismCount);
    if (rv != CKR_OK) {
        efree(pMechanismList);
        pkcs11_error(rv, "Unable to get mechanism list from token 2");
        return;
    }

    uint i;
    array_init(return_value);
    for (i=0; i<ulMechanismCount; i++) {
        add_next_index_long(return_value, pMechanismList[i]);
    }
    efree(pMechanismList);
}


PHP_METHOD(Module, getMechanismInfo) {

    zend_long slotId;
    zend_long mechanismId;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_LONG(slotId)
        Z_PARAM_LONG(mechanismId)
    ZEND_PARSE_PARAMETERS_END();

    CK_RV rv;
    CK_MECHANISM_INFO mechanismInfo;

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);

    if (!objval->initialised) {
        zend_throw_exception(zend_ce_exception, "Uninitialised PKCS11 module", 0);
        return;
    }

    rv = objval->functionList->C_GetMechanismInfo(slotId, mechanismId, &mechanismInfo);
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to get slot info from token");
        return;
    }

    array_init(return_value);
    add_assoc_long(return_value, "min_key_size", mechanismInfo.ulMinKeySize);
    add_assoc_long(return_value, "max_key_size", mechanismInfo.ulMaxKeySize);
}


PHP_METHOD(Module, initToken) {
    char *var;
    size_t var_len;
    zend_string *retval;
    CK_RV rv;
    CK_ULONG ulSlotCount;
    CK_SLOT_ID_PTR pSlotList;
    CK_SLOT_INFO slotInfo;


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
    rv = objval->functionList->C_InitToken(slotid, (CK_UTF8CHAR_PTR)sopin_str, ZSTR_LEN(sopin_str), (CK_UTF8CHAR_PTR)label_str);
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to initialise token");
        return;
    }
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
    zval *retval = emalloc(sizeof(zval));

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(session)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);
    pkcs11_session_object *sessionobjval = Z_PKCS11_SESSION_P(session);

    call_obj_func(&sessionobjval->std, "getInfo", return_value, 0, NULL);
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

    PHP_MALIAS(Module, C_GetInfo,          getInfo,          arginfo_getInfo,          ZEND_ACC_PUBLIC)
    PHP_MALIAS(Module, C_GetSlots,         getSlots,         arginfo_getSlots,         ZEND_ACC_PUBLIC)
    PHP_MALIAS(Module, C_GetSlotList,      getSlotList,      arginfo_getSlotList,      ZEND_ACC_PUBLIC)
    PHP_MALIAS(Module, C_GetSlotInfo,      getSlotInfo,      arginfo_getSlotInfo,      ZEND_ACC_PUBLIC)
    PHP_MALIAS(Module, C_GetTokenInfo,     getTokenInfo,     arginfo_getTokenInfo,     ZEND_ACC_PUBLIC)
    PHP_MALIAS(Module, C_GetMechanismList, getMechanismList, arginfo_getMechanismList, ZEND_ACC_PUBLIC)
    PHP_MALIAS(Module, C_GetMechanismInfo, getMechanismInfo, arginfo_getMechanismInfo, ZEND_ACC_PUBLIC)
    PHP_MALIAS(Module, C_InitToken,        initToken,        arginfo_initToken,        ZEND_ACC_PUBLIC)
    PHP_MALIAS(Module, C_OpenSession,      openSession,      arginfo_openSession,      ZEND_ACC_PUBLIC)

    PHP_ME(Module, C_GetSessionInfo,          arginfo_C_GetSessionInfo,          ZEND_ACC_PUBLIC)

    PHP_FE_END
};


DEFINE_MAGIC_FUNCS(pkcs11, module, Module)
