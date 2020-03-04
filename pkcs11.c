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
    CK_ULONG ulSlotCount;
    CK_SLOT_ID_PTR pSlotList;
    CK_SLOT_INFO slotInfo;

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
    /*
    rv = objval->functionList->C_GetSlotList(CK_FALSE, NULL_PTR, &ulSlotCount);
    assert(rv == CKR_OK);

    pSlotList = (CK_SLOT_ID_PTR) malloc(ulSlotCount * sizeof(CK_SLOT_ID));
    rv = objval->functionList->C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
    assert(rv == CKR_OK);

    uint i;
    for (i=0; i<ulSlotCount; i++) {
        printf("%d \n", i);
        rv = objval->functionList->C_GetSlotInfo(pSlotList[i], &slotInfo);
        assert(rv == CKR_OK);
        printf("%s\n", slotInfo.slotDescription);
    }
    */

}

PHP_METHOD(Module, getInfo) {
    char *var;
    size_t var_len;
    zend_string *retval;
    CK_RV rv;
    CK_INFO info;

    pkcs11_object *objval = Z_PKCS11_P(ZEND_THIS);

    if (!objval->initialised) {
        zend_throw_exception(zend_ce_exception, "Uninitialised PKCS11 module", 0);
        return;
    }

    rv = objval->functionList->C_GetInfo(&info);
    assert(rv == CKR_OK);
    if (info.cryptokiVersion.major == 2) {
        printf("Is version 2\n");
    } else {
        printf("Is _not_ version 2\n");
    }
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_module___construct, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, module_path, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_module_getInfo, 0, 0, 0)
    ZEND_ARG_TYPE_INFO(0, var, IS_STRING, 0)
ZEND_END_ARG_INFO()

static zend_class_entry *ce_Pkcs11_Module;
static zend_object_handlers pkcs11_handlers;

static zend_function_entry module_class_functions[] = {
    PHP_ME(Module, __construct, arginfo_pkcs11_module___construct, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    PHP_ME(Module, getInfo, arginfo_pkcs11_module_getInfo, ZEND_ACC_PUBLIC)
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
