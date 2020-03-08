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


#define Z_PKCS11_P(zv)  pkcs11_from_zend_object(Z_OBJ_P((zv)))

static inline pkcs11_object* pkcs11_from_zend_object(zend_object *obj) {
    return ((pkcs11_object*)(obj + 1)) - 1;
}

void pkcs11_error(char* generic, char* specific) {
    char buf[256];
    sprintf(buf, "%s: %s", generic, specific);
    zend_throw_exception(zend_ce_exception, buf, 0);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_module___construct, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, module_path, IS_STRING, 0)
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
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_module_getSlotInfo, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, module_path, IS_LONG, 0)
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
    ZEND_ARG_TYPE_INFO(0, module_path, IS_LONG, 0)
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

static zend_class_entry *ce_Pkcs11_Module;
static zend_object_handlers pkcs11_handlers;

static zend_function_entry module_class_functions[] = {
    PHP_ME(Module, __construct, arginfo_pkcs11_module___construct, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    PHP_ME(Module, getInfo, arginfo_pkcs11_module_getInfo, ZEND_ACC_PUBLIC)
    PHP_ME(Module, getSlots, arginfo_pkcs11_module_getSlots, ZEND_ACC_PUBLIC)
    PHP_ME(Module, getSlotList, arginfo_pkcs11_module_getSlotList, ZEND_ACC_PUBLIC)
    PHP_ME(Module, getSlotInfo, arginfo_pkcs11_module_getSlotInfo, ZEND_ACC_PUBLIC)
    PHP_ME(Module, getTokenInfo, arginfo_pkcs11_module_getTokenInfo, ZEND_ACC_PUBLIC)
    PHP_ME(Module, initToken, arginfo_pkcs11_module_initToken, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

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

    zend_object_std_dtor(zobj);
}

PHP_MINIT_FUNCTION(pkcs11)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Pkcs11", "Module", module_class_functions);
    ce_Pkcs11_Module = zend_register_internal_class(&ce);
    ce_Pkcs11_Module->create_object = pkcs11_ctor;

    memcpy(&pkcs11_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    pkcs11_handlers.offset = XtOffsetOf(pkcs11_object, std);
    pkcs11_handlers.free_obj = pkcs11_dtor;

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
