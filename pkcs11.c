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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "zend_exceptions.h"
#include "zend_interfaces.h"
#include "ext/standard/info.h"
#include "php_pkcs11.h"

#include <stdbool.h>
#include <dlfcn.h>
#include <assert.h>

/* For compatibility with older PHP versions */
#ifndef ZEND_PARSE_PARAMETERS_NONE
#define ZEND_PARSE_PARAMETERS_NONE() \
    ZEND_PARSE_PARAMETERS_START(0, 0) \
    ZEND_PARSE_PARAMETERS_END()
#endif

typedef struct _pkcs11_object {
    bool initialised;
    void *pkcs11module;
    CK_FUNCTION_LIST_PTR functionList;
    zend_object std;
} pkcs11_object;

typedef struct _pkcs11_session_object {
    pkcs11_object *pkcs11;
    CK_SESSION_HANDLE session;
    CK_SLOT_ID slotID;
    zend_object std;
} pkcs11_session_object;

typedef struct _pkcs11_key_object {
    pkcs11_session_object *session;
    CK_OBJECT_HANDLE key;
    zend_object std;
} pkcs11_key_object;

typedef struct _pkcs11_keypair_object {
    pkcs11_key_object *pkey;
    pkcs11_key_object *skey;
    zend_object std;
} pkcs11_keypair_object;

typedef struct _pkcs11_rsapssparams_object {
    CK_RSA_PKCS_PSS_PARAMS params;
    zend_object std;
} pkcs11_rsapssparams_object;

typedef struct _pkcs11_rsaoaepparams_object {
    CK_RSA_PKCS_OAEP_PARAMS params;
    zend_object std;
} pkcs11_rsaoaepparams_object;

typedef struct _pkcs11_gcmparams_object {
    CK_GCM_PARAMS params;
    zend_object std;
} pkcs11_gcmparams_object;


#define Z_PKCS11_P(zv)  pkcs11_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_SESSION_P(zv)  pkcs11_session_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_KEY_P(zv)  pkcs11_key_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_KEYPAIR_P(zv)  pkcs11_keypair_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_RSAPSSPARAMS_P(zv)  pkcs11_rsapssparams_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_RSAOAEPPARAMS_P(zv)  pkcs11_rsaoaepparams_from_zend_object(Z_OBJ_P((zv)))
#define Z_PKCS11_GCMPARAMS_P(zv)  pkcs11_gcmparams_from_zend_object(Z_OBJ_P((zv)))

static inline pkcs11_object* pkcs11_from_zend_object(zend_object *obj) {
    return (pkcs11_object*)((char*)(obj) - XtOffsetOf(pkcs11_object, std));
}

static inline pkcs11_session_object* pkcs11_session_from_zend_object(zend_object *obj) {
    return (pkcs11_session_object*)((char*)(obj) - XtOffsetOf(pkcs11_session_object, std));
}

static inline pkcs11_key_object* pkcs11_key_from_zend_object(zend_object *obj) {
    return (pkcs11_key_object*)((char*)(obj) - XtOffsetOf(pkcs11_key_object, std));
}

static inline pkcs11_keypair_object* pkcs11_keypair_from_zend_object(zend_object *obj) {
    return (pkcs11_keypair_object*)((char*)(obj) - XtOffsetOf(pkcs11_keypair_object, std));
}

static inline pkcs11_rsapssparams_object* pkcs11_rsapssparams_from_zend_object(zend_object *obj) {
    return (pkcs11_rsapssparams_object*)((char*)(obj) - XtOffsetOf(pkcs11_rsapssparams_object, std));
}

static inline pkcs11_rsaoaepparams_object* pkcs11_rsaoaepparams_from_zend_object(zend_object *obj) {
    return (pkcs11_rsaoaepparams_object*)((char*)(obj) - XtOffsetOf(pkcs11_rsaoaepparams_object, std));
}

static inline pkcs11_gcmparams_object* pkcs11_gcmparams_from_zend_object(zend_object *obj) {
    return (pkcs11_gcmparams_object*)((char*)(obj) - XtOffsetOf(pkcs11_gcmparams_object, std));
}

static zend_class_entry *ce_Pkcs11_Module;
static zend_object_handlers pkcs11_handlers;

static zend_class_entry *ce_Pkcs11_Session;
static zend_object_handlers pkcs11_session_handlers;

static zend_class_entry *ce_Pkcs11_Key;
static zend_object_handlers pkcs11_key_handlers;

static zend_class_entry *ce_Pkcs11_KeyPair;
static zend_object_handlers pkcs11_keypair_handlers;

static zend_class_entry *ce_Pkcs11_RsaPssParams;
static zend_object_handlers pkcs11_rsapssparams_handlers;

static zend_class_entry *ce_Pkcs11_RsaOaepParams;
static zend_object_handlers pkcs11_rsaoaepparams_handlers;

static zend_class_entry *ce_Pkcs11_GcmParams;
static zend_object_handlers pkcs11_gcmparams_handlers;

void pkcs11_error(char* generic, char* specific) {
    char buf[256];
    sprintf(buf, "%s: %s", generic, specific);
    zend_throw_exception(zend_ce_exception, buf, 0);
}

void parseTemplate(HashTable **template, CK_ATTRIBUTE_PTR *templateObj, int *templateItemCount) {
    zval *templateValue;
    zend_ulong templateValueKey;
    *templateItemCount = zend_hash_num_elements(*template);
    *templateObj = calloc(*templateItemCount, sizeof(CK_ATTRIBUTE));
    unsigned int i = 0;
    CK_BBOOL btrue = CK_TRUE;
    CK_BBOOL bfalse = CK_FALSE;
    ZEND_HASH_FOREACH_NUM_KEY_VAL(*template, templateValueKey, templateValue)
        if (Z_TYPE_P(templateValue) == IS_LONG) {
            (*templateObj)[i] = (CK_ATTRIBUTE){templateValueKey, &(Z_LVAL_P(templateValue)), sizeof(CK_ULONG)};

        } else if (Z_TYPE_P(templateValue) == IS_STRING) {
            (*templateObj)[i] = (CK_ATTRIBUTE){templateValueKey, Z_STRVAL_P(templateValue), Z_STRLEN_P(templateValue)};

        } else if (Z_TYPE_P(templateValue) == IS_TRUE) {
            (*templateObj)[i] = (CK_ATTRIBUTE){templateValueKey, &btrue, sizeof(btrue)};

        } else if (Z_TYPE_P(templateValue) == IS_FALSE) {
            (*templateObj)[i] = (CK_ATTRIBUTE){templateValueKey, &bfalse, sizeof(bfalse)};

        } else {
            pkcs11_error("Unable to parse template", "Unsupported parameter type");
        }

        i++;
    ZEND_HASH_FOREACH_END();
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_module___construct, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, modulePath, IS_STRING, 0)
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
        pkcs11_error("Unable to initialise PKCS11 module", dlerror_str);
        return;
    }

    CK_C_GetFunctionList C_GetFunctionList = dlsym(objval->pkcs11module, "C_GetFunctionList");
    dlerror_str = dlerror();
    if (dlerror_str != NULL) {
        pkcs11_error("Unable to initialise PKCS11 module", dlerror_str);
        return;
    }

    rv = C_GetFunctionList(&objval->functionList);
    if (rv != CKR_OK) {
        pkcs11_error("PKCS11 module error", "Unable to retrieve functio list");
        return;
    }

    rv = objval->functionList->C_Initialize(NULL);
    if (rv != CKR_OK) {
        pkcs11_error("PKCS11 module error", "Unable to initialise token");
        return;
    }

    objval->initialised = true;
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_module_getInfo, 0, 0, 0)
ZEND_END_ARG_INFO()

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
        pkcs11_error("PKCS11 module error", "Unable to get information from token");
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_module_getSlots, 0, 0, 0)
ZEND_END_ARG_INFO()

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
        pkcs11_error("PKCS11 module error", "Unable to get slot list from token");
        return;
    }

    pSlotList = (CK_SLOT_ID_PTR) malloc(ulSlotCount * sizeof(CK_SLOT_ID));
    rv = objval->functionList->C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
    if (rv != CKR_OK) {
        free(pSlotList);
        pkcs11_error("PKCS11 module error", "Unable to get slot list from token");
        return;
    }

    uint i;
    zval slotObj;
    array_init(return_value);
    for (i=0; i<ulSlotCount; i++) {
        rv = objval->functionList->C_GetSlotInfo(pSlotList[i], &slotInfo);
        if (rv != CKR_OK) {
            pkcs11_error("PKCS11 module error", "Unable to get slot info from token");
            return;
        }

        array_init(&slotObj);
        add_assoc_long(&slotObj, "id", pSlotList[i]);
        add_assoc_stringl(&slotObj, "description", slotInfo.slotDescription, 64);
        add_index_zval(return_value, pSlotList[i], &slotObj);
    }
    free(pSlotList);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_module_getSlotList, 0, 0, 0)
ZEND_END_ARG_INFO()

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
        pkcs11_error("PKCS11 module error", "Unable to get slot list from token");
        return;
    }

    pSlotList = (CK_SLOT_ID_PTR) malloc(ulSlotCount * sizeof(CK_SLOT_ID));
    rv = objval->functionList->C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
    if (rv != CKR_OK) {
        pkcs11_error("PKCS11 module error", "Unable to get slot list from token");
        return;
    }

    uint i;
    array_init(return_value);
    for (i=0; i<ulSlotCount; i++) {
        add_next_index_long(return_value, pSlotList[i]);
    }

    free(pSlotList);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_module_getSlotInfo, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, slotId, IS_LONG, 0)
ZEND_END_ARG_INFO()

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
        pkcs11_error("PKCS11 module error", "Unable to get slot info from token");
        return;
    }

    array_init(return_value);
    add_assoc_long(return_value, "id", slotId);
    add_assoc_stringl(return_value, "description", slotInfo.slotDescription, 64);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_module_getTokenInfo, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, slotId, IS_LONG, 0)
ZEND_END_ARG_INFO()

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
        pkcs11_error("PKCS11 module error", "Unable to get slot info from token");
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_module_getMechanismList, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, slotId, IS_LONG, 0)
ZEND_END_ARG_INFO()

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
        pkcs11_error("PKCS11 module error", "Unable to get mechanism list from token 1");
        return;
    }

    pMechanismList = (CK_MECHANISM_TYPE_PTR) malloc(ulMechanismCount * sizeof(CK_MECHANISM_TYPE));
    rv = objval->functionList->C_GetMechanismList(slotId, pMechanismList, &ulMechanismCount);
    if (rv != CKR_OK) {
        free(pMechanismList);
        pkcs11_error("PKCS11 module error", "Unable to get mechanism list from token 2");
        return;
    }

    uint i;
    array_init(return_value);
    for (i=0; i<ulMechanismCount; i++) {
        add_next_index_long(return_value, pMechanismList[i]);
    }
    free(pMechanismList);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_module_getMechanismInfo, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, slotId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, mechanismId, IS_LONG, 0)
ZEND_END_ARG_INFO()

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
        pkcs11_error("PKCS11 module error", "Unable to get slot info from token");
        return;
    }

    array_init(return_value);
    add_assoc_long(return_value, "min_key_size", mechanismInfo.ulMinKeySize);
    add_assoc_long(return_value, "max_key_size", mechanismInfo.ulMaxKeySize);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_module_initToken, 0, 0, 3)
    ZEND_ARG_TYPE_INFO(0, slotid, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, label, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, sopin, IS_STRING, 0)
ZEND_END_ARG_INFO()

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
        pkcs11_error("PKCS11 module error", "Unable to initialise token");
        return;
    }
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_module_openSession, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, slotid, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
ZEND_END_ARG_INFO()

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
        pkcs11_error("PKCS11 module error", "Unable to open session");
        return;
    }
    session_obj->session = phSession;
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_session_getInfo, 0, 0, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Session, getInfo) {

    CK_RV rv;
    CK_SESSION_INFO sessionInfo;

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);
    rv = objval->pkcs11->functionList->C_GetSessionInfo(objval->session, &sessionInfo);

    if (rv != CKR_OK) {
        pkcs11_error("PKCS11 module error", "Unable to get session info");
        return;
    }

    array_init(return_value);
    add_assoc_long(return_value, "state", sessionInfo.state);
    add_assoc_long(return_value, "flags", sessionInfo.flags);
    add_assoc_long(return_value, "device_error", sessionInfo.ulDeviceError);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_session_login, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, loginType, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, pin, IS_STRING, 0)
ZEND_END_ARG_INFO()

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
        pkcs11_error("PKCS11 module error", "Unable to login");
        return;
    }
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_session_logout, 0, 0, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Session, logout) {

    CK_RV rv;

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);
    rv = objval->pkcs11->functionList->C_Logout(objval->session);
    if (rv != CKR_OK) {
        pkcs11_error("PKCS11 module error", "Unable to logout");
        return;
    }
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_session_initPin, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, pin, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Session, initPin) {

    CK_RV rv;
    zend_string *newPin;

    ZEND_PARSE_PARAMETERS_START(1,1)
        Z_PARAM_STR(newPin)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);
    rv = objval->pkcs11->functionList->C_InitPIN(objval->session, ZSTR_VAL(newPin), ZSTR_LEN(newPin));

    if (rv != CKR_OK) {
        pkcs11_error("PKCS11 module error", "Unable to set pin");
        return;
    }
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_session_setPin, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, oldPin, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, newPin, IS_STRING, 0)
ZEND_END_ARG_INFO()

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
        pkcs11_error("PKCS11 module error", "Unable to set pin");
        return;
    }
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_session_generateKey, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, mechanismId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, template, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

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
    CK_ATTRIBUTE *templateObj;
    parseTemplate(&template, &templateObj, &templateItemCount);

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);
    rv = objval->pkcs11->functionList->C_GenerateKey(
        objval->session,
        &mechanism,
        templateObj, templateItemCount, &hKey
    );

    if (rv != CKR_OK) {
        php_printf("%ld\n", rv);
        pkcs11_error("PKCS11 module error", "Unable to generate key");
        return;
    }

    pkcs11_key_object* key_obj;

    object_init_ex(return_value, ce_Pkcs11_Key);
    key_obj = Z_PKCS11_KEY_P(return_value);
    key_obj->session = objval;
    key_obj->key = hKey;
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_session_generateKeyPair, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, mechanismId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, pkTemplate, IS_ARRAY, 0)
    ZEND_ARG_TYPE_INFO(0, skTemplate, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

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
    CK_ATTRIBUTE *skTemplateObj;
    parseTemplate(&skTemplate, &skTemplateObj, &skTemplateItemCount);

    int pkTemplateItemCount;
    CK_ATTRIBUTE *pkTemplateObj;
    parseTemplate(&pkTemplate, &pkTemplateObj, &pkTemplateItemCount);

    rv = objval->pkcs11->functionList->C_GenerateKeyPair(
        objval->session,
        &mechanism,
        pkTemplateObj, pkTemplateItemCount,
        skTemplateObj, skTemplateItemCount,
        &pKey, &sKey
    );

    if (rv != CKR_OK) {
        php_printf("Error code: %ld\n", rv);
        pkcs11_error("PKCS11 module error", "Unable to generate key pair");
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_session_findObjects, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, template, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Session, findObjects) {

    CK_RV rv;
    HashTable *template;
    zval *templateValue;
    zend_ulong templateValueKey;

    ZEND_PARSE_PARAMETERS_START(1,1)
        Z_PARAM_ARRAY_HT(template)
    ZEND_PARSE_PARAMETERS_END();

    int templateItemCount;
    CK_ATTRIBUTE *templateObj;
    parseTemplate(&template, &templateObj, &templateItemCount);

    pkcs11_session_object *objval = Z_PKCS11_SESSION_P(ZEND_THIS);
    rv = objval->pkcs11->functionList->C_FindObjectsInit(objval->session, templateObj, templateItemCount);
    if (rv != CKR_OK) {
        pkcs11_error("PKCS11 module error", "Unable to find objects");
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
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_key_sign, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, mechanismId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, mechanismArgument, IS_OBJECT, 1)
ZEND_END_ARG_INFO()

PHP_METHOD(Key, sign) {

    CK_RV rv;
    zend_long mechanismId;
    zend_string *data;
    zval *mechanismArgument = NULL;

    ZEND_PARSE_PARAMETERS_START(2,3)
        Z_PARAM_LONG(mechanismId)
        Z_PARAM_STR(data)
        Z_PARAM_OPTIONAL
        Z_PARAM_ZVAL(mechanismArgument)
    ZEND_PARSE_PARAMETERS_END();

    CK_MECHANISM mechanism = {mechanismId, NULL_PTR, 0};
    CK_VOID_PTR pParams;

    if (mechanismArgument) {
        if(zend_string_equals_literal(Z_OBJ_P(mechanismArgument)->ce->name, "Pkcs11\\RsaPssParams")) {
            pkcs11_rsapssparams_object *mechanismObj = Z_PKCS11_RSAPSSPARAMS_P(mechanismArgument);
            mechanism.pParameter = &mechanismObj->params;
            mechanism.ulParameterLen = sizeof(mechanismObj->params);
        }
    }

    pkcs11_key_object *objval = Z_PKCS11_KEY_P(ZEND_THIS);
    rv = objval->session->pkcs11->functionList->C_SignInit(
        objval->session->session,
        &mechanism,
        objval->key
    );
    if (rv != CKR_OK) {
        php_printf("%ld\n", rv);
        pkcs11_error("PKCS11 module error", "Unable to sign");
        return;
    }

    CK_ULONG signatureLen;
    rv = objval->session->pkcs11->functionList->C_Sign(
        objval->session->session,
        ZSTR_VAL(data),
        ZSTR_LEN(data),
        NULL_PTR,
        &signatureLen
    );
    if (rv != CKR_OK) {
        php_printf("%ld\n", rv);
        pkcs11_error("PKCS11 module error", "Unable to sign");
        return;
    }

    CK_BYTE_PTR signature = calloc(signatureLen, sizeof(CK_BYTE));
    rv = objval->session->pkcs11->functionList->C_Sign(
        objval->session->session,
        ZSTR_VAL(data),
        ZSTR_LEN(data),
        signature,
        &signatureLen
    );
    if (rv != CKR_OK) {
        php_printf("%ld\n", rv);
        pkcs11_error("PKCS11 module error", "Unable to sign");
        return;
    }

    zend_string *returnval;
    returnval = zend_string_alloc(signatureLen, 0);
    memcpy(
        ZSTR_VAL(returnval),
        signature,
        signatureLen
    );
    RETURN_STR(returnval);
 
    free(pParams);
    free(signature);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_key_getAttributeValue, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, attributeIds, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Key, getAttributeValue) {

    CK_RV rv;
    zval *attributeIds;
    zval *attributeId;
    unsigned int i;

    ZEND_PARSE_PARAMETERS_START(1,1)
        Z_PARAM_ARRAY(attributeIds)
    ZEND_PARSE_PARAMETERS_END();

    int attributeIdCount = zend_hash_num_elements(Z_ARRVAL_P(attributeIds));

    CK_ATTRIBUTE *template = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) * attributeIdCount);

    i = 0;
    ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(attributeIds), attributeId) {
        if (Z_TYPE_P(attributeId) != IS_LONG) {
            pkcs11_error("PKCS11 module error", "Unable to get attribute value. Attribute ID must be an integer");
            return;
        }
        template[i] = (CK_ATTRIBUTE) {zval_get_long(attributeId), NULL_PTR, 0};
        i++;
    } ZEND_HASH_FOREACH_END();

    pkcs11_key_object *objval = Z_PKCS11_KEY_P(ZEND_THIS);
    rv = objval->session->pkcs11->functionList->C_GetAttributeValue(
        objval->session->session,
        objval->key,
        template,
        attributeIdCount
    );
    if (rv != CKR_OK) {
        php_printf("%ld\n", rv);
        pkcs11_error("PKCS11 module error", "Unable to get attribute value");
        return;
    }

    for (i=0; i<attributeIdCount; i++) {
        template[i].pValue = (uint8_t *) calloc(1, template[i].ulValueLen);
    }

    rv = objval->session->pkcs11->functionList->C_GetAttributeValue(
        objval->session->session,
        objval->key,
        template,
        attributeIdCount
    );
    if (rv != CKR_OK) {
        php_printf("%ld\n", rv);
        pkcs11_error("PKCS11 module error", "Unable to get attribute value");
        return;
    }

    array_init(return_value);
    for (i=0; i<attributeIdCount; i++) {
        zend_string *foo;
        foo = zend_string_alloc(template[i].ulValueLen, 0);
        memcpy(
            ZSTR_VAL(foo),
            template[i].pValue,
            template[i].ulValueLen
        );

        add_index_str(return_value, template[i].type, foo);
    }

    free(template);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_key_encrypt, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, mechanismId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, plaintext, IS_STRING, 0)
    ZEND_ARG_INFO(0, mechanismArgument)
ZEND_END_ARG_INFO()

PHP_METHOD(Key, encrypt) {

    CK_RV rv;
    zend_long mechanismId;
    zend_string *plaintext;
    zval *mechanismArgument = NULL;

    ZEND_PARSE_PARAMETERS_START(2,3)
        Z_PARAM_LONG(mechanismId)
        Z_PARAM_STR(plaintext)
        Z_PARAM_OPTIONAL
        Z_PARAM_ZVAL(mechanismArgument)
    ZEND_PARSE_PARAMETERS_END();

    CK_MECHANISM mechanism = {mechanismId, NULL_PTR, 0};

    if (mechanismArgument) {
        if (Z_TYPE_P(mechanismArgument) == IS_STRING) {
            mechanism.pParameter = Z_STRVAL_P(mechanismArgument);
            mechanism.ulParameterLen = Z_STRLEN_P(mechanismArgument);

        } else if (Z_TYPE_P(mechanismArgument) == IS_OBJECT) {
            if(zend_string_equals_literal(Z_OBJ_P(mechanismArgument)->ce->name, "Pkcs11\\GcmParams")) {
                pkcs11_gcmparams_object *mechanismObj = Z_PKCS11_GCMPARAMS_P(mechanismArgument);
                mechanism.pParameter = &mechanismObj->params;
                mechanism.ulParameterLen = sizeof(mechanismObj->params);
            
            } else if(zend_string_equals_literal(Z_OBJ_P(mechanismArgument)->ce->name, "Pkcs11\\RsaOaepParams")) {
                pkcs11_rsaoaepparams_object *mechanismObj = Z_PKCS11_RSAOAEPPARAMS_P(mechanismArgument);
                mechanism.pParameter = &mechanismObj->params;
                mechanism.ulParameterLen = sizeof(mechanismObj->params);
            }
        }
    }

    pkcs11_key_object *objval = Z_PKCS11_KEY_P(ZEND_THIS);
    rv = objval->session->pkcs11->functionList->C_EncryptInit(
        objval->session->session,
        &mechanism,
        objval->key
    );
    if (rv != CKR_OK) {
        php_printf("%ld\n", rv);
        pkcs11_error("PKCS11 module error", "Unable to encrypt");
        return;
    }

    CK_ULONG ciphertextLen;
    rv = objval->session->pkcs11->functionList->C_Encrypt(
        objval->session->session,
        ZSTR_VAL(plaintext),
        ZSTR_LEN(plaintext),
        NULL_PTR ,
        &ciphertextLen
    );
    if (rv != CKR_OK) {
        php_printf("%ld\n", rv);
        pkcs11_error("PKCS11 module error", "Unable to encrypt");
        return;
    }

    CK_BYTE_PTR ciphertext = calloc(ciphertextLen, sizeof(CK_BYTE));
    rv = objval->session->pkcs11->functionList->C_Encrypt(
        objval->session->session,
        ZSTR_VAL(plaintext),
        ZSTR_LEN(plaintext),
        ciphertext,
        &ciphertextLen
    );
    if (rv != CKR_OK) {
        php_printf("%ld\n", rv);
        pkcs11_error("PKCS11 module error", "Unable to encrypt");
        return;
    }

    zend_string *returnval;
    returnval = zend_string_alloc(ciphertextLen, 0);
    memcpy(
        ZSTR_VAL(returnval),
        ciphertext,
        ciphertextLen
    );
    RETURN_STR(returnval);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_key_decrypt, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, mechanismId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, ciphertext, IS_STRING, 0)
    ZEND_ARG_INFO(0, mechanismArgument)
ZEND_END_ARG_INFO()

PHP_METHOD(Key, decrypt) {

    CK_RV rv;
    zend_long mechanismId;
    zend_string *ciphertext;
    zval *mechanismArgument = NULL;

    ZEND_PARSE_PARAMETERS_START(2,3)
        Z_PARAM_LONG(mechanismId)
        Z_PARAM_STR(ciphertext)
        Z_PARAM_OPTIONAL
        Z_PARAM_ZVAL(mechanismArgument)
    ZEND_PARSE_PARAMETERS_END();

    CK_MECHANISM mechanism = {mechanismId, NULL_PTR, 0};

    if (mechanismArgument) {
        if (Z_TYPE_P(mechanismArgument) == IS_STRING) {
            mechanism.pParameter = Z_STRVAL_P(mechanismArgument);
            mechanism.ulParameterLen = Z_STRLEN_P(mechanismArgument);

        } else if (Z_TYPE_P(mechanismArgument) == IS_OBJECT) {
            if(zend_string_equals_literal(Z_OBJ_P(mechanismArgument)->ce->name, "Pkcs11\\GcmParams")) {
                pkcs11_gcmparams_object *mechanismObj = Z_PKCS11_GCMPARAMS_P(mechanismArgument);
                mechanism.pParameter = &mechanismObj->params;
                mechanism.ulParameterLen = sizeof(mechanismObj->params);
            
            } else if(zend_string_equals_literal(Z_OBJ_P(mechanismArgument)->ce->name, "Pkcs11\\RsaOaepParams")) {
                pkcs11_rsaoaepparams_object *mechanismObj = Z_PKCS11_RSAOAEPPARAMS_P(mechanismArgument);
                mechanism.pParameter = &mechanismObj->params;
                mechanism.ulParameterLen = sizeof(mechanismObj->params);
            }
        }
    }

    pkcs11_key_object *objval = Z_PKCS11_KEY_P(ZEND_THIS);
    rv = objval->session->pkcs11->functionList->C_DecryptInit(
        objval->session->session,
        &mechanism,
        objval->key
    );
    if (rv != CKR_OK) {
        php_printf("%ld\n", rv);
        pkcs11_error("PKCS11 module error", "Unable to decrypt");
        return;
    }

    CK_ULONG plaintextLen;
    rv = objval->session->pkcs11->functionList->C_Decrypt(
        objval->session->session,
        ZSTR_VAL(ciphertext),
        ZSTR_LEN(ciphertext),
        NULL_PTR,
        &plaintextLen
    );
    if (rv != CKR_OK) {
        php_printf("%ld\n", rv);
        pkcs11_error("PKCS11 module error", "Unable to decrypt");
        return;
    }

    CK_BYTE_PTR plaintext = calloc(plaintextLen, sizeof(CK_BYTE));
    rv = objval->session->pkcs11->functionList->C_Decrypt(
        objval->session->session,
        ZSTR_VAL(ciphertext),
        ZSTR_LEN(ciphertext),
        plaintext,
        &plaintextLen
    );
    if (rv != CKR_OK) {
        php_printf("%ld\n", rv);
        pkcs11_error("PKCS11 module error", "Unable to decrypt");
        return;
    }

    zend_string *returnval;
    returnval = zend_string_alloc(plaintextLen, 0);
    memcpy(
        ZSTR_VAL(returnval),
        plaintext,
        plaintextLen
    );
    RETURN_STR(returnval);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_rsapssparams___construct, 0, 0, 3)
    ZEND_ARG_TYPE_INFO(0, mechanismId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, mgfId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, sLen, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(RsaPssParams, __construct) {

    CK_RV rv;
    zend_long mechanismId;
    zend_long mgfId;
    zend_long sLen;

    ZEND_PARSE_PARAMETERS_START(3,3)
        Z_PARAM_LONG(mechanismId)
        Z_PARAM_LONG(mgfId)
        Z_PARAM_LONG(sLen)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_rsapssparams_object *objval = Z_PKCS11_RSAPSSPARAMS_P(ZEND_THIS);
    objval->params.hashAlg = mechanismId;
    objval->params.mgf = mgfId;
    objval->params.sLen = sLen;
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_rsaoaepparams___construct, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, mechanismId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, mgfId, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, source, IS_STRING, 1)
ZEND_END_ARG_INFO()

PHP_METHOD(RsaOaepParams, __construct) {

    CK_RV rv;
    zend_long mechanismId;
    zend_long mgfId;
    zend_string *source = NULL;

    ZEND_PARSE_PARAMETERS_START(2,3)
        Z_PARAM_LONG(mechanismId)
        Z_PARAM_LONG(mgfId)
        Z_PARAM_OPTIONAL
        Z_PARAM_STR(source)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_rsaoaepparams_object *objval = Z_PKCS11_RSAOAEPPARAMS_P(ZEND_THIS);
    objval->params.hashAlg = mechanismId;
    objval->params.mgf = mgfId;
    objval->params.source = CKZ_DATA_SPECIFIED;
    if (source && ZSTR_LEN(source) > 0) {
        objval->params.pSourceData = ZSTR_VAL(source);
        objval->params.ulSourceDataLen = ZSTR_LEN(source);
    }
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_gcmparams___construct, 0, 0, 3)
    ZEND_ARG_TYPE_INFO(0, iv, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, aad, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, sTagLen, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(GcmParams, __construct) {

    CK_RV rv;
    zend_string *iv;
    zend_string *aad;
    zend_long sTagLen;

    ZEND_PARSE_PARAMETERS_START(3,3)
        Z_PARAM_STR(iv)
        Z_PARAM_STR(aad)
        Z_PARAM_LONG(sTagLen)
    ZEND_PARSE_PARAMETERS_END();

    pkcs11_gcmparams_object *objval = Z_PKCS11_GCMPARAMS_P(ZEND_THIS);
    objval->params.pIv = ZSTR_VAL(iv);
    objval->params.ulIvLen = ZSTR_LEN(iv);
    objval->params.pAAD = ZSTR_VAL(aad);
    objval->params.ulAADLen = ZSTR_LEN(aad);
    objval->params.ulTagBits = sTagLen;
}

static zend_object* pkcs11_ctor(zend_class_entry *ce) {
    pkcs11_object *objval = zend_object_alloc(sizeof(pkcs11_object), ce);

    zend_object_std_init(&objval->std, ce);
    object_properties_init(&objval->std, ce);
    objval->std.handlers = &pkcs11_handlers;

    return &objval->std;
}

static void pkcs11_dtor(zend_object *zobj) {

    pkcs11_object *objval = pkcs11_from_zend_object(zobj);

    if (objval->functionList != NULL) {
        objval->functionList->C_Finalize(NULL_PTR);
    }

    if (objval->pkcs11module != NULL) {
        dlclose(objval->pkcs11module);
    }

    zend_object_std_dtor(&objval->std);
}

static zend_function_entry module_class_functions[] = {
    PHP_ME(Module, __construct, arginfo_pkcs11_module___construct, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    PHP_ME(Module, getInfo, arginfo_pkcs11_module_getInfo, ZEND_ACC_PUBLIC)
    PHP_ME(Module, getSlots, arginfo_pkcs11_module_getSlots, ZEND_ACC_PUBLIC)
    PHP_ME(Module, getSlotList, arginfo_pkcs11_module_getSlotList, ZEND_ACC_PUBLIC)
    PHP_ME(Module, getSlotInfo, arginfo_pkcs11_module_getSlotInfo, ZEND_ACC_PUBLIC)
    PHP_ME(Module, getTokenInfo, arginfo_pkcs11_module_getTokenInfo, ZEND_ACC_PUBLIC)
    PHP_ME(Module, getMechanismList, arginfo_pkcs11_module_getMechanismList, ZEND_ACC_PUBLIC)
    PHP_ME(Module, getMechanismInfo, arginfo_pkcs11_module_getMechanismInfo, ZEND_ACC_PUBLIC)
    PHP_ME(Module, initToken, arginfo_pkcs11_module_initToken, ZEND_ACC_PUBLIC)
    PHP_ME(Module, openSession, arginfo_pkcs11_module_openSession, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static zend_object* pkcs11_session_ctor(zend_class_entry *ce) {
    pkcs11_session_object *objval = zend_object_alloc(sizeof(pkcs11_session_object), ce);

    zend_object_std_init(&objval->std, ce);
    object_properties_init(&objval->std, ce);
    objval->std.handlers = &pkcs11_session_handlers;

    return &objval->std;
}

static void pkcs11_session_dtor(zend_object *zobj) {

    pkcs11_session_object *objval = pkcs11_session_from_zend_object(zobj);

    if (objval->pkcs11->functionList != NULL) {
        objval->pkcs11->functionList->C_CloseSession(objval->session);
    }

    zend_object_std_dtor(&objval->std);
}

static zend_function_entry session_class_functions[] = {
    PHP_ME(Session, login, arginfo_pkcs11_session_login, ZEND_ACC_PUBLIC)
    PHP_ME(Session, getInfo, arginfo_pkcs11_session_getInfo, ZEND_ACC_PUBLIC)
    PHP_ME(Session, logout, arginfo_pkcs11_session_logout, ZEND_ACC_PUBLIC)
    PHP_ME(Session, initPin, arginfo_pkcs11_session_initPin, ZEND_ACC_PUBLIC)
    PHP_ME(Session, setPin, arginfo_pkcs11_session_setPin, ZEND_ACC_PUBLIC)
    PHP_ME(Session, findObjects, arginfo_pkcs11_session_findObjects, ZEND_ACC_PUBLIC)
    PHP_ME(Session, generateKey, arginfo_pkcs11_session_generateKey, ZEND_ACC_PUBLIC)
    PHP_ME(Session, generateKeyPair, arginfo_pkcs11_session_generateKeyPair, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static zend_object* pkcs11_key_ctor(zend_class_entry *ce) {
    pkcs11_key_object *objval = zend_object_alloc(sizeof(pkcs11_key_object), ce);

    zend_object_std_init(&objval->std, ce);
    object_properties_init(&objval->std, ce);
    objval->std.handlers = &pkcs11_key_handlers;

    return &objval->std;
}

static void pkcs11_key_dtor(zend_object *zobj) {

    pkcs11_key_object *objval = pkcs11_key_from_zend_object(zobj);

    zend_object_std_dtor(&objval->std);
}

static zend_function_entry key_class_functions[] = {
    PHP_ME(Key, encrypt, arginfo_pkcs11_key_encrypt, ZEND_ACC_PUBLIC)
    PHP_ME(Key, decrypt, arginfo_pkcs11_key_decrypt, ZEND_ACC_PUBLIC)
    PHP_ME(Key, sign, arginfo_pkcs11_key_sign, ZEND_ACC_PUBLIC)
    PHP_ME(Key, getAttributeValue, arginfo_pkcs11_key_getAttributeValue, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static zend_object* pkcs11_keypair_ctor(zend_class_entry *ce) {
    pkcs11_keypair_object *objval = zend_object_alloc(sizeof(pkcs11_keypair_object), ce);

    zend_object_std_init(&objval->std, ce);
    object_properties_init(&objval->std, ce);
    objval->std.handlers = &pkcs11_keypair_handlers;

    return &objval->std;
}

static void pkcs11_keypair_dtor(zend_object *zobj) {

    pkcs11_keypair_object *objval = pkcs11_keypair_from_zend_object(zobj);

    zend_object_std_dtor(&objval->std);
}

static zend_function_entry keypair_class_functions[] = {
    PHP_FE_END
};

static zend_object* pkcs11_rsapssparams_ctor(zend_class_entry *ce) {
    pkcs11_rsapssparams_object *objval = zend_object_alloc(sizeof(pkcs11_rsapssparams_object), ce);

    zend_object_std_init(&objval->std, ce);
    object_properties_init(&objval->std, ce);
    objval->std.handlers = &pkcs11_rsapssparams_handlers;

    return &objval->std;
}

static void pkcs11_rsapssparams_dtor(zend_object *zobj) {

    pkcs11_rsapssparams_object *objval = pkcs11_rsapssparams_from_zend_object(zobj);

    zend_object_std_dtor(&objval->std);
}

static zend_function_entry rsapssparams_class_functions[] = {
    PHP_ME(RsaPssParams, __construct, arginfo_pkcs11_rsapssparams___construct, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    PHP_FE_END
};

static zend_object* pkcs11_rsaoaepparams_ctor(zend_class_entry *ce) {
    pkcs11_rsaoaepparams_object *objval = zend_object_alloc(sizeof(pkcs11_rsaoaepparams_object), ce);

    zend_object_std_init(&objval->std, ce);
    object_properties_init(&objval->std, ce);
    objval->std.handlers = &pkcs11_rsaoaepparams_handlers;

    return &objval->std;
}

static void pkcs11_rsaoaepparams_dtor(zend_object *zobj) {

    pkcs11_rsaoaepparams_object *objval = pkcs11_rsaoaepparams_from_zend_object(zobj);

    zend_object_std_dtor(&objval->std);
}

static zend_function_entry rsaoaepparams_class_functions[] = {
    PHP_ME(RsaOaepParams, __construct, arginfo_pkcs11_rsaoaepparams___construct, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    PHP_FE_END
};

static zend_object* pkcs11_gcmparams_ctor(zend_class_entry *ce) {
    pkcs11_gcmparams_object *objval = zend_object_alloc(sizeof(pkcs11_gcmparams_object), ce);

    zend_object_std_init(&objval->std, ce);
    object_properties_init(&objval->std, ce);
    objval->std.handlers = &pkcs11_gcmparams_handlers;

    return &objval->std;
}

static void pkcs11_gcmparams_dtor(zend_object *zobj) {

    pkcs11_gcmparams_object *objval = pkcs11_gcmparams_from_zend_object(zobj);

    zend_object_std_dtor(&objval->std);
}

static zend_function_entry gcmparams_class_functions[] = {
    PHP_ME(GcmParams, __construct, arginfo_pkcs11_gcmparams___construct, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    PHP_FE_END
};

PHP_MINIT_FUNCTION(pkcs11)
{
    zend_class_entry ce;

    memcpy(&pkcs11_handlers, &std_object_handlers, sizeof(zend_object_handlers));
    INIT_NS_CLASS_ENTRY(ce, "Pkcs11", "Module", module_class_functions);
    ce.create_object = pkcs11_ctor;
    pkcs11_handlers.offset = XtOffsetOf(pkcs11_object, std);
    pkcs11_handlers.clone_obj = NULL;
    pkcs11_handlers.free_obj = pkcs11_dtor;
    ce_Pkcs11_Module = zend_register_internal_class(&ce);
    ce_Pkcs11_Module->serialize = zend_class_serialize_deny;
    ce_Pkcs11_Module->unserialize = zend_class_unserialize_deny;

    memcpy(&pkcs11_session_handlers, &std_object_handlers, sizeof(zend_object_handlers));
    INIT_NS_CLASS_ENTRY(ce, "Pkcs11", "Session", session_class_functions);
    ce.create_object = pkcs11_session_ctor;
    pkcs11_session_handlers.offset = XtOffsetOf(pkcs11_session_object, std);
    pkcs11_session_handlers.clone_obj = NULL;
    pkcs11_session_handlers.free_obj = pkcs11_session_dtor;
    ce_Pkcs11_Session = zend_register_internal_class(&ce);
    ce_Pkcs11_Session->serialize = zend_class_serialize_deny;
    ce_Pkcs11_Session->unserialize = zend_class_unserialize_deny;

    memcpy(&pkcs11_key_handlers, &std_object_handlers, sizeof(zend_object_handlers));
    INIT_NS_CLASS_ENTRY(ce, "Pkcs11", "Key", key_class_functions);
    ce.create_object = pkcs11_key_ctor;
    pkcs11_key_handlers.offset = XtOffsetOf(pkcs11_key_object, std);
    pkcs11_key_handlers.clone_obj = NULL;
    pkcs11_key_handlers.free_obj = pkcs11_key_dtor;
    ce_Pkcs11_Key = zend_register_internal_class(&ce);
    ce_Pkcs11_Key->serialize = zend_class_serialize_deny;
    ce_Pkcs11_Key->unserialize = zend_class_unserialize_deny;

    memcpy(&pkcs11_keypair_handlers, &std_object_handlers, sizeof(zend_object_handlers));
    INIT_NS_CLASS_ENTRY(ce, "Pkcs11", "KeyPair", keypair_class_functions);
    ce.create_object = pkcs11_keypair_ctor;
    pkcs11_keypair_handlers.offset = XtOffsetOf(pkcs11_keypair_object, std);
    pkcs11_keypair_handlers.clone_obj = NULL;
    pkcs11_keypair_handlers.free_obj = pkcs11_keypair_dtor;
    ce_Pkcs11_KeyPair = zend_register_internal_class(&ce);
    ce_Pkcs11_KeyPair->serialize = zend_class_serialize_deny;
    ce_Pkcs11_KeyPair->unserialize = zend_class_unserialize_deny;

    memcpy(&pkcs11_rsapssparams_handlers, &std_object_handlers, sizeof(zend_object_handlers));
    INIT_NS_CLASS_ENTRY(ce, "Pkcs11", "RsaPssParams", rsapssparams_class_functions);
    ce.create_object = pkcs11_rsapssparams_ctor;
    pkcs11_rsapssparams_handlers.offset = XtOffsetOf(pkcs11_rsapssparams_object, std);
    pkcs11_rsapssparams_handlers.clone_obj = NULL;
    pkcs11_rsapssparams_handlers.free_obj = pkcs11_rsapssparams_dtor;
    ce_Pkcs11_RsaPssParams = zend_register_internal_class(&ce);
    ce_Pkcs11_RsaPssParams->serialize = zend_class_serialize_deny;
    ce_Pkcs11_RsaPssParams->unserialize = zend_class_unserialize_deny;

    memcpy(&pkcs11_rsaoaepparams_handlers, &std_object_handlers, sizeof(zend_object_handlers));
    INIT_NS_CLASS_ENTRY(ce, "Pkcs11", "RsaOaepParams", rsaoaepparams_class_functions);
    ce.create_object = pkcs11_rsaoaepparams_ctor;
    pkcs11_rsaoaepparams_handlers.offset = XtOffsetOf(pkcs11_rsaoaepparams_object, std);
    pkcs11_rsaoaepparams_handlers.clone_obj = NULL;
    pkcs11_rsaoaepparams_handlers.free_obj = pkcs11_rsaoaepparams_dtor;
    ce_Pkcs11_RsaOaepParams = zend_register_internal_class(&ce);
    ce_Pkcs11_RsaOaepParams->serialize = zend_class_serialize_deny;
    ce_Pkcs11_RsaOaepParams->unserialize = zend_class_unserialize_deny;

    memcpy(&pkcs11_gcmparams_handlers, &std_object_handlers, sizeof(zend_object_handlers));
    INIT_NS_CLASS_ENTRY(ce, "Pkcs11", "GcmParams", gcmparams_class_functions);
    ce.create_object = pkcs11_gcmparams_ctor;
    pkcs11_gcmparams_handlers.offset = XtOffsetOf(pkcs11_gcmparams_object, std);
    pkcs11_gcmparams_handlers.clone_obj = NULL;
    pkcs11_gcmparams_handlers.free_obj = pkcs11_gcmparams_dtor;
    ce_Pkcs11_GcmParams = zend_register_internal_class(&ce);
    ce_Pkcs11_GcmParams->serialize = zend_class_serialize_deny;
    ce_Pkcs11_GcmParams->unserialize = zend_class_unserialize_deny;

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RSA_PKCS_KEY_PAIR_GEN",      0x00000000UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RSA_PKCS",                   0x00000001UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RSA_9796",                   0x00000002UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RSA_X_509",                  0x00000003UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_MD2_RSA_PKCS",               0x00000004UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_MD5_RSA_PKCS",               0x00000005UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA1_RSA_PKCS",              0x00000006UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RIPEMD128_RSA_PKCS",         0x00000007UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RIPEMD160_RSA_PKCS",         0x00000008UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RSA_PKCS_OAEP",              0x00000009UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RSA_X9_31_KEY_PAIR_GEN",     0x0000000AUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RSA_X9_31",                  0x0000000BUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA1_RSA_X9_31",             0x0000000CUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RSA_PKCS_PSS",               0x0000000DUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA1_RSA_PKCS_PSS",          0x0000000EUL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DSA_KEY_PAIR_GEN",           0x00000010UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DSA",                        0x00000011UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DSA_SHA1",                   0x00000012UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DSA_SHA224",                 0x00000013UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DSA_SHA256",                 0x00000014UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DSA_SHA384",                 0x00000015UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DSA_SHA512",                 0x00000016UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DH_PKCS_KEY_PAIR_GEN",       0x00000020UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DH_PKCS_DERIVE",             0x00000021UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_X9_42_DH_KEY_PAIR_GEN",      0x00000030UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_X9_42_DH_DERIVE",            0x00000031UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_X9_42_DH_HYBRID_DERIVE",     0x00000032UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_X9_42_MQV_DERIVE",           0x00000033UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA256_RSA_PKCS",            0x00000040UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA384_RSA_PKCS",            0x00000041UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA512_RSA_PKCS",            0x00000042UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA256_RSA_PKCS_PSS",        0x00000043UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA384_RSA_PKCS_PSS",        0x00000044UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA512_RSA_PKCS_PSS",        0x00000045UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA224_RSA_PKCS",            0x00000046UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA224_RSA_PKCS_PSS",        0x00000047UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA512_224",                 0x00000048UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA512_224_HMAC",            0x00000049UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA512_224_HMAC_GENERAL",    0x0000004AUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA512_224_KEY_DERIVATION",  0x0000004BUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA512_256",                 0x0000004CUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA512_256_HMAC",            0x0000004DUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA512_256_HMAC_GENERAL",    0x0000004EUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA512_256_KEY_DERIVATION",  0x0000004FUL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA512_T",                   0x00000050UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA512_T_HMAC",              0x00000051UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA512_T_HMAC_GENERAL",      0x00000052UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA512_T_KEY_DERIVATION",    0x00000053UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RC2_KEY_GEN",                0x00000100UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RC2_ECB",                    0x00000101UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RC2_CBC",                    0x00000102UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RC2_MAC",                    0x00000103UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RC2_MAC_GENERAL",            0x00000104UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RC2_CBC_PAD",                0x00000105UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RC4_KEY_GEN",                0x00000110UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RC4",                        0x00000111UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DES_KEY_GEN",                0x00000120UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DES_ECB",                    0x00000121UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DES_CBC",                    0x00000122UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DES_MAC",                    0x00000123UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DES_MAC_GENERAL",            0x00000124UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DES_CBC_PAD",                0x00000125UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DES2_KEY_GEN",               0x00000130UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DES3_KEY_GEN",               0x00000131UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DES3_ECB",                   0x00000132UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DES3_CBC",                   0x00000133UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DES3_MAC",                   0x00000134UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DES3_MAC_GENERAL",           0x00000135UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DES3_CBC_PAD",               0x00000136UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DES3_CMAC_GENERAL",          0x00000137UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DES3_CMAC",                  0x00000138UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CDMF_KEY_GEN",               0x00000140UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CDMF_ECB",                   0x00000141UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CDMF_CBC",                   0x00000142UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CDMF_MAC",                   0x00000143UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CDMF_MAC_GENERAL",           0x00000144UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CDMF_CBC_PAD",               0x00000145UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DES_OFB64",                  0x00000150UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DES_OFB8",                   0x00000151UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DES_CFB64",                  0x00000152UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DES_CFB8",                   0x00000153UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_MD2",                        0x00000200UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_MD2_HMAC",                   0x00000201UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_MD2_HMAC_GENERAL",           0x00000202UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_MD5",                        0x00000210UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_MD5_HMAC",                   0x00000211UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_MD5_HMAC_GENERAL",           0x00000212UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA_1",                      0x00000220UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA_1_HMAC",                 0x00000221UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA_1_HMAC_GENERAL",         0x00000222UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RIPEMD128",                  0x00000230UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RIPEMD128_HMAC",             0x00000231UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RIPEMD128_HMAC_GENERAL",     0x00000232UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RIPEMD160",                  0x00000240UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RIPEMD160_HMAC",             0x00000241UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RIPEMD160_HMAC_GENERAL",     0x00000242UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA256",                     0x00000250UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA256_HMAC",                0x00000251UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA256_HMAC_GENERAL",        0x00000252UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA224",                     0x00000255UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA224_HMAC",                0x00000256UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA224_HMAC_GENERAL",        0x00000257UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA384",                     0x00000260UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA384_HMAC",                0x00000261UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA384_HMAC_GENERAL",        0x00000262UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA512",                     0x00000270UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA512_HMAC",                0x00000271UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA512_HMAC_GENERAL",        0x00000272UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SECURID_KEY_GEN",            0x00000280UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SECURID",                    0x00000282UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_HOTP_KEY_GEN",               0x00000290UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_HOTP",                       0x00000291UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_ACTI",                       0x000002A0UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_ACTI_KEY_GEN",               0x000002A1UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST_KEY_GEN",               0x00000300UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST_ECB",                   0x00000301UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST_CBC",                   0x00000302UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST_MAC",                   0x00000303UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST_MAC_GENERAL",           0x00000304UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST_CBC_PAD",               0x00000305UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST3_KEY_GEN",              0x00000310UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST3_ECB",                  0x00000311UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST3_CBC",                  0x00000312UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST3_MAC",                  0x00000313UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST3_MAC_GENERAL",          0x00000314UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST3_CBC_PAD",              0x00000315UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST5_KEY_GEN",              0x00000320UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST128_KEY_GEN",            0x00000320UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST5_ECB",                  0x00000321UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST128_ECB",                0x00000321UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST5_CBC",                  0x00000322UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST128_CBC",                0x00000322UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST5_MAC",                  0x00000323UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST128_MAC",                0x00000323UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST5_MAC_GENERAL",          0x00000324UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST128_MAC_GENERAL",        0x00000324UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST5_CBC_PAD",              0x00000325UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAST128_CBC_PAD",            0x00000325UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RC5_KEY_GEN",                0x00000330UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RC5_ECB",                    0x00000331UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RC5_CBC",                    0x00000332UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RC5_MAC",                    0x00000333UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RC5_MAC_GENERAL",            0x00000334UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RC5_CBC_PAD",                0x00000335UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_IDEA_KEY_GEN",               0x00000340UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_IDEA_ECB",                   0x00000341UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_IDEA_CBC",                   0x00000342UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_IDEA_MAC",                   0x00000343UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_IDEA_MAC_GENERAL",           0x00000344UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_IDEA_CBC_PAD",               0x00000345UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_GENERIC_SECRET_KEY_GEN",     0x00000350UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CONCATENATE_BASE_AND_KEY",   0x00000360UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CONCATENATE_BASE_AND_DATA",  0x00000362UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CONCATENATE_DATA_AND_BASE",  0x00000363UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_XOR_BASE_AND_DATA",          0x00000364UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_EXTRACT_KEY_FROM_KEY",       0x00000365UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SSL3_PRE_MASTER_KEY_GEN",    0x00000370UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SSL3_MASTER_KEY_DERIVE",     0x00000371UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SSL3_KEY_AND_MAC_DERIVE",    0x00000372UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SSL3_MASTER_KEY_DERIVE_DH",  0x00000373UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_TLS_PRE_MASTER_KEY_GEN",     0x00000374UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_TLS_MASTER_KEY_DERIVE",      0x00000375UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_TLS_KEY_AND_MAC_DERIVE",     0x00000376UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_TLS_MASTER_KEY_DERIVE_DH",   0x00000377UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_TLS_PRF",                    0x00000378UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SSL3_MD5_MAC",               0x00000380UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SSL3_SHA1_MAC",              0x00000381UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_MD5_KEY_DERIVATION",         0x00000390UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_MD2_KEY_DERIVATION",         0x00000391UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA1_KEY_DERIVATION",        0x00000392UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA256_KEY_DERIVATION",      0x00000393UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA384_KEY_DERIVATION",      0x00000394UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA512_KEY_DERIVATION",      0x00000395UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SHA224_KEY_DERIVATION",      0x00000396UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_PBE_MD2_DES_CBC",            0x000003A0UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_PBE_MD5_DES_CBC",            0x000003A1UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_PBE_MD5_CAST_CBC",           0x000003A2UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_PBE_MD5_CAST3_CBC",          0x000003A3UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_PBE_MD5_CAST5_CBC",          0x000003A4UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_PBE_MD5_CAST128_CBC",        0x000003A4UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_PBE_SHA1_CAST5_CBC",         0x000003A5UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_PBE_SHA1_CAST128_CBC",       0x000003A5UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_PBE_SHA1_RC4_128",           0x000003A6UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_PBE_SHA1_RC4_40",            0x000003A7UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_PBE_SHA1_DES3_EDE_CBC",      0x000003A8UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_PBE_SHA1_DES2_EDE_CBC",      0x000003A9UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_PBE_SHA1_RC2_128_CBC",       0x000003AAUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_PBE_SHA1_RC2_40_CBC",        0x000003ABUL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_PKCS5_PBKD2",                0x000003B0UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_PBA_SHA1_WITH_SHA1_HMAC",    0x000003C0UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_WTLS_PRE_MASTER_KEY_GEN",         0x000003D0UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_WTLS_MASTER_KEY_DERIVE",          0x000003D1UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC",   0x000003D2UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_WTLS_PRF",                        0x000003D3UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE",  0x000003D4UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE",  0x000003D5UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_TLS10_MAC_SERVER",                0x000003D6UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_TLS10_MAC_CLIENT",                0x000003D7UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_TLS12_MAC",                       0x000003D8UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_TLS12_KDF",                       0x000003D9UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_TLS12_MASTER_KEY_DERIVE",         0x000003E0UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_TLS12_KEY_AND_MAC_DERIVE",        0x000003E1UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_TLS12_MASTER_KEY_DERIVE_DH",      0x000003E2UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_TLS12_KEY_SAFE_DERIVE",           0x000003E3UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_TLS_MAC",                         0x000003E4UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_TLS_KDF",                         0x000003E5UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_KEY_WRAP_LYNKS",             0x00000400UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_KEY_WRAP_SET_OAEP",          0x00000401UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CMS_SIG",                    0x00000500UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_KIP_DERIVE",                 0x00000510UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_KIP_WRAP",                   0x00000511UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_KIP_MAC",                    0x00000512UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAMELLIA_KEY_GEN",           0x00000550UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAMELLIA_ECB",               0x00000551UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAMELLIA_CBC",               0x00000552UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAMELLIA_MAC",               0x00000553UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAMELLIA_MAC_GENERAL",       0x00000554UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAMELLIA_CBC_PAD",           0x00000555UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAMELLIA_ECB_ENCRYPT_DATA",  0x00000556UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAMELLIA_CBC_ENCRYPT_DATA",  0x00000557UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_CAMELLIA_CTR",               0x00000558UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_ARIA_KEY_GEN",               0x00000560UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_ARIA_ECB",                   0x00000561UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_ARIA_CBC",                   0x00000562UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_ARIA_MAC",                   0x00000563UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_ARIA_MAC_GENERAL",           0x00000564UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_ARIA_CBC_PAD",               0x00000565UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_ARIA_ECB_ENCRYPT_DATA",      0x00000566UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_ARIA_CBC_ENCRYPT_DATA",      0x00000567UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SEED_KEY_GEN",               0x00000650UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SEED_ECB",                   0x00000651UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SEED_CBC",                   0x00000652UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SEED_MAC",                   0x00000653UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SEED_MAC_GENERAL",           0x00000654UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SEED_CBC_PAD",               0x00000655UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SEED_ECB_ENCRYPT_DATA",      0x00000656UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SEED_CBC_ENCRYPT_DATA",      0x00000657UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SKIPJACK_KEY_GEN",           0x00001000UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SKIPJACK_ECB64",             0x00001001UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SKIPJACK_CBC64",             0x00001002UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SKIPJACK_OFB64",             0x00001003UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SKIPJACK_CFB64",             0x00001004UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SKIPJACK_CFB32",             0x00001005UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SKIPJACK_CFB16",             0x00001006UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SKIPJACK_CFB8",              0x00001007UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SKIPJACK_WRAP",              0x00001008UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SKIPJACK_PRIVATE_WRAP",      0x00001009UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_SKIPJACK_RELAYX",            0x0000100aUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_KEA_KEY_PAIR_GEN",           0x00001010UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_KEA_KEY_DERIVE",             0x00001011UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_KEA_DERIVE",                 0x00001012UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_FORTEZZA_TIMESTAMP",         0x00001020UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_BATON_KEY_GEN",              0x00001030UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_BATON_ECB128",               0x00001031UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_BATON_ECB96",                0x00001032UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_BATON_CBC128",               0x00001033UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_BATON_COUNTER",              0x00001034UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_BATON_SHUFFLE",              0x00001035UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_BATON_WRAP",                 0x00001036UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_ECDSA_KEY_PAIR_GEN",         0x00001040UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_EC_KEY_PAIR_GEN",            0x00001040UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_ECDSA",                      0x00001041UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_ECDSA_SHA1",                 0x00001042UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_ECDSA_SHA224",               0x00001043UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_ECDSA_SHA256",               0x00001044UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_ECDSA_SHA384",               0x00001045UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_ECDSA_SHA512",               0x00001046UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_ECDH1_DERIVE",               0x00001050UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_ECDH1_COFACTOR_DERIVE",      0x00001051UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_ECMQV_DERIVE",               0x00001052UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_ECDH_AES_KEY_WRAP",          0x00001053UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RSA_AES_KEY_WRAP",           0x00001054UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_JUNIPER_KEY_GEN",            0x00001060UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_JUNIPER_ECB128",             0x00001061UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_JUNIPER_CBC128",             0x00001062UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_JUNIPER_COUNTER",            0x00001063UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_JUNIPER_SHUFFLE",            0x00001064UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_JUNIPER_WRAP",               0x00001065UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_FASTHASH",                   0x00001070UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_KEY_GEN",                0x00001080UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_ECB",                    0x00001081UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_CBC",                    0x00001082UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_MAC",                    0x00001083UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_MAC_GENERAL",            0x00001084UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_CBC_PAD",                0x00001085UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_CTR",                    0x00001086UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_GCM",                    0x00001087UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_CCM",                    0x00001088UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_CTS",                    0x00001089UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_CMAC",                   0x0000108AUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_CMAC_GENERAL",           0x0000108BUL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_XCBC_MAC",               0x0000108CUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_XCBC_MAC_96",            0x0000108DUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_GMAC",                   0x0000108EUL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_BLOWFISH_KEY_GEN",           0x00001090UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_BLOWFISH_CBC",               0x00001091UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_TWOFISH_KEY_GEN",            0x00001092UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_TWOFISH_CBC",                0x00001093UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_BLOWFISH_CBC_PAD",           0x00001094UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_TWOFISH_CBC_PAD",            0x00001095UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DES_ECB_ENCRYPT_DATA",       0x00001100UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DES_CBC_ENCRYPT_DATA",       0x00001101UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DES3_ECB_ENCRYPT_DATA",      0x00001102UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DES3_CBC_ENCRYPT_DATA",      0x00001103UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_ECB_ENCRYPT_DATA",       0x00001104UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_CBC_ENCRYPT_DATA",       0x00001105UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_GOSTR3410_KEY_PAIR_GEN",     0x00001200UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_GOSTR3410",                  0x00001201UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_GOSTR3410_WITH_GOSTR3411",   0x00001202UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_GOSTR3410_KEY_WRAP",         0x00001203UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_GOSTR3410_DERIVE",           0x00001204UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_GOSTR3411",                  0x00001210UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_GOSTR3411_HMAC",             0x00001211UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_GOST28147_KEY_GEN",          0x00001220UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_GOST28147_ECB",              0x00001221UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_GOST28147",                  0x00001222UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_GOST28147_MAC",              0x00001223UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_GOST28147_KEY_WRAP",         0x00001224UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DSA_PARAMETER_GEN",          0x00002000UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DH_PKCS_PARAMETER_GEN",      0x00002001UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_X9_42_DH_PARAMETER_GEN",     0x00002002UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DSA_PROBABLISTIC_PARAMETER_GEN",    0x00002003UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN",    0x00002004UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_OFB",                    0x00002104UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_CFB64",                  0x00002105UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_CFB8",                   0x00002106UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_CFB128",                 0x00002107UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_CFB1",                   0x00002108UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_KEY_WRAP",               0x00002109UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_AES_KEY_WRAP_PAD",           0x0000210AUL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RSA_PKCS_TPM_1_1",           0x00004001UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKM_RSA_PKCS_OAEP_TPM_1_1",      0x00004002UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKF_RW_SESSION",                 0x00000002UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKF_SERIAL_SESSION",             0x00000004UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKU_SO",                         0x00000000UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKU_USER",                       0x00000001UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKU_CONTEXT_SPECIFIC",           0x00000002UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKS_RO_PUBLIC_SESSION",          0x00000000UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKS_RO_USER_FUNCTIONS",          0x00000001UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKS_RW_PUBLIC_SESSION",          0x00000002UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKS_RW_USER_FUNCTIONS",          0x00000003UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKS_RW_SO_FUNCTIONS",            0x00000004UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_CLASS",                      0x00000000UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_TOKEN",                      0x00000001UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_PRIVATE",                    0x00000002UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_LABEL",                      0x00000003UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_APPLICATION",                0x00000010UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_VALUE",                      0x00000011UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_OBJECT_ID",                  0x00000012UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_CERTIFICATE_TYPE",           0x00000080UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_ISSUER",                     0x00000081UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_SERIAL_NUMBER",              0x00000082UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_AC_ISSUER",                  0x00000083UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_OWNER",                      0x00000084UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_ATTR_TYPES",                 0x00000085UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_TRUSTED",                    0x00000086UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_CERTIFICATE_CATEGORY",       0x00000087UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_JAVA_MIDP_SECURITY_DOMAIN",  0x00000088UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_URL",                        0x00000089UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_HASH_OF_SUBJECT_PUBLIC_KEY", 0x0000008AUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_HASH_OF_ISSUER_PUBLIC_KEY",  0x0000008BUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_NAME_HASH_ALGORITHM",        0x0000008CUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_CHECK_VALUE",                0x00000090UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_KEY_TYPE",                   0x00000100UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_SUBJECT",                    0x00000101UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_ID",                         0x00000102UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_SENSITIVE",                  0x00000103UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_ENCRYPT",                    0x00000104UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_DECRYPT",                    0x00000105UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_WRAP",                       0x00000106UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_UNWRAP",                     0x00000107UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_SIGN",                       0x00000108UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_SIGN_RECOVER",               0x00000109UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_VERIFY",                     0x0000010AUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_VERIFY_RECOVER",             0x0000010BUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_DERIVE",                     0x0000010CUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_START_DATE",                 0x00000110UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_END_DATE",                   0x00000111UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_MODULUS",                    0x00000120UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_MODULUS_BITS",               0x00000121UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_PUBLIC_EXPONENT",            0x00000122UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_PRIVATE_EXPONENT",           0x00000123UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_PRIME_1",                    0x00000124UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_PRIME_2",                    0x00000125UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_EXPONENT_1",                 0x00000126UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_EXPONENT_2",                 0x00000127UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_COEFFICIENT",                0x00000128UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_PUBLIC_KEY_INFO",            0x00000129UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_PRIME",                      0x00000130UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_SUBPRIME",                   0x00000131UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_BASE",                       0x00000132UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_PRIME_BITS",                 0x00000133UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_SUBPRIME_BITS",              0x00000134UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_SUB_PRIME_BITS",             CKA_SUBPRIME_BITS, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_VALUE_BITS",                 0x00000160UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_VALUE_LEN",                  0x00000161UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_EXTRACTABLE",                0x00000162UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_LOCAL",                      0x00000163UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_NEVER_EXTRACTABLE",          0x00000164UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_ALWAYS_SENSITIVE",           0x00000165UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_KEY_GEN_MECHANISM",          0x00000166UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_MODIFIABLE",                 0x00000170UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_COPYABLE",                   0x00000171UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_DESTROYABLE",                0x00000172UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_ECDSA_PARAMS",               0x00000180UL /* Deprecated */, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_EC_PARAMS",                  0x00000180UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_EC_POINT",                   0x00000181UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_SECONDARY_AUTH",             0x00000200UL /* Deprecated */, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_AUTH_PIN_FLAGS",             0x00000201UL /* Deprecated */, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_ALWAYS_AUTHENTICATE",        0x00000202UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_WRAP_WITH_TRUSTED",          0x00000210UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_WRAP_TEMPLATE",              (CKF_ARRAY_ATTRIBUTE|0x00000211UL), CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_UNWRAP_TEMPLATE",            (CKF_ARRAY_ATTRIBUTE|0x00000212UL), CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_DERIVE_TEMPLATE",            (CKF_ARRAY_ATTRIBUTE|0x00000213UL), CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_OTP_FORMAT",                 0x00000220UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_OTP_LENGTH",                 0x00000221UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_OTP_TIME_INTERVAL",          0x00000222UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_OTP_USER_FRIENDLY_MODE",     0x00000223UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_OTP_CHALLENGE_REQUIREMENT",  0x00000224UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_OTP_TIME_REQUIREMENT",       0x00000225UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_OTP_COUNTER_REQUIREMENT",    0x00000226UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_OTP_PIN_REQUIREMENT",        0x00000227UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_OTP_COUNTER",                0x0000022EUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_OTP_TIME",                   0x0000022FUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_OTP_USER_IDENTIFIER",        0x0000022AUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_OTP_SERVICE_IDENTIFIER",     0x0000022BUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_OTP_SERVICE_LOGO",           0x0000022CUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_OTP_SERVICE_LOGO_TYPE",      0x0000022DUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_GOSTR3410_PARAMS",           0x00000250UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_GOSTR3411_PARAMS",           0x00000251UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_GOST28147_PARAMS",           0x00000252UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_HW_FEATURE_TYPE",            0x00000300UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_RESET_ON_INIT",              0x00000301UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_HAS_RESET",                  0x00000302UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_PIXEL_X",                    0x00000400UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_PIXEL_Y",                    0x00000401UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_RESOLUTION",                 0x00000402UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_CHAR_ROWS",                  0x00000403UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_CHAR_COLUMNS",               0x00000404UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_COLOR",                      0x00000405UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_BITS_PER_PIXEL",             0x00000406UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_CHAR_SETS",                  0x00000480UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_ENCODING_METHODS",           0x00000481UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_MIME_TYPES",                 0x00000482UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_MECHANISM_TYPE",             0x00000500UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_REQUIRED_CMS_ATTRIBUTES",    0x00000501UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_DEFAULT_CMS_ATTRIBUTES",     0x00000502UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_SUPPORTED_CMS_ATTRIBUTES",   0x00000503UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_ALLOWED_MECHANISMS",         (CKF_ARRAY_ATTRIBUTE|0x00000600UL), CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKA_VENDOR_DEFINED",             0x80000000UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKO_DATA",                       0x00000000UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKO_CERTIFICATE",                0x00000001UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKO_PUBLIC_KEY",                 0x00000002UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKO_PRIVATE_KEY",                0x00000003UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKO_SECRET_KEY",                 0x00000004UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKO_HW_FEATURE",                 0x00000005UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKO_DOMAIN_PARAMETERS",          0x00000006UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKO_MECHANISM",                  0x00000007UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKO_OTP_KEY",                    0x00000008UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKO_VENDOR_DEFINED",             0x80000000UL, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_RSA",                        0x00000000UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_DSA",                        0x00000001UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_DH",                         0x00000002UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_ECDSA",                      0x00000003UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_EC",                         0x00000003UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_X9_42_DH",                   0x00000004UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_KEA",                        0x00000005UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_GENERIC_SECRET",             0x00000010UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_RC2",                        0x00000011UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_RC4",                        0x00000012UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_DES",                        0x00000013UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_DES2",                       0x00000014UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_DES3",                       0x00000015UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_CAST",                       0x00000016UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_CAST3",                      0x00000017UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_CAST5",                      0x00000018UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_CAST128",                    0x00000018UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_RC5",                        0x00000019UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_IDEA",                       0x0000001AUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_SKIPJACK",                   0x0000001BUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_BATON",                      0x0000001CUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_JUNIPER",                    0x0000001DUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_CDMF",                       0x0000001EUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_AES",                        0x0000001FUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_BLOWFISH",                   0x00000020UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_TWOFISH",                    0x00000021UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_SECURID",                    0x00000022UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_HOTP",                       0x00000023UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_ACTI",                       0x00000024UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_CAMELLIA",                   0x00000025UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_ARIA",                       0x00000026UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_MD5_HMAC",                   0x00000027UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_SHA_1_HMAC",                 0x00000028UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_RIPEMD128_HMAC",             0x00000029UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_RIPEMD160_HMAC",             0x0000002AUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_SHA256_HMAC",                0x0000002BUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_SHA384_HMAC",                0x0000002CUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_SHA512_HMAC",                0x0000002DUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_SHA224_HMAC",                0x0000002EUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_SEED",                       0x0000002FUL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_GOSTR3410",                  0x00000030UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_GOSTR3411",                  0x00000031UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_GOST28147",                  0x00000032UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKK_VENDOR_DEFINED",             0x80000000UL, CONST_CS | CONST_PERSISTENT);
    
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKG_MGF1_SHA1",                  0x00000001UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKG_MGF1_SHA256",                0x00000002UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKG_MGF1_SHA384",                0x00000003UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKG_MGF1_SHA512",                0x00000004UL, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKG_MGF1_SHA224",                0x00000005UL, CONST_CS | CONST_PERSISTENT);
    
    REGISTER_NS_LONG_CONSTANT("Pkcs11", "CKZ_DATA_SPECIFIED",             0x00000001UL, CONST_CS | CONST_PERSISTENT);

    return SUCCESS;
}

PHP_MINFO_FUNCTION(pkcs11)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "pkcs11 support", "enabled");
    php_info_print_table_end();
}

zend_module_entry pkcs11_module_entry = {
    STANDARD_MODULE_HEADER,
    "pkcs11",
    NULL,                           /* zend_function_entry */
    PHP_MINIT(pkcs11),              /* PHP_MINIT - Module initialization */
    NULL,                           /* PHP_MSHUTDOWN - Module shutdown */
    NULL,                           /* PHP_RINIT - Request initialization */
    NULL,                           /* PHP_RSHUTDOWN - Request shutdown */
    PHP_MINFO(pkcs11),              /* PHP_MINFO - Module info */
    PHP_PKCS11_VERSION,             /* Version */
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_PKCS11
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(pkcs11)
#endif
