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

#include <dlfcn.h>
#include <assert.h>

/* For compatibility with older PHP versions */
#ifndef ZEND_PARSE_PARAMETERS_NONE
#define ZEND_PARSE_PARAMETERS_NONE() \
	ZEND_PARSE_PARAMETERS_START(0, 0) \
	ZEND_PARSE_PARAMETERS_END()
#endif

typedef struct _pkcs11_object {
	int initialised;
    CK_FUNCTION_LIST_PTR functionList;
    zend_object std;
} pkcs11_object;

static zend_object* pkcs11_to_zend_object(pkcs11_object *objval) {
    return ((zend_object*)(objval + 1)) - 1;
}
static pkcs11_object* pkcs11_from_zend_object(zend_object *objval) {
    return ((pkcs11_object*)(objval + 1)) - 1;
}


PHP_METHOD(Module, __construct) {
	char *module_path;
	size_t module_path_len;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_PATH(module_path, module_path_len)
	ZEND_PARSE_PARAMETERS_END();

	pkcs11_object *objval = pkcs11_from_zend_object(Z_OBJ_P(getThis()));

		printf("%d\n", objval->initialised);
	if (objval->initialised == 0) {
		zend_throw_exception(zend_ce_exception, "Already initialised PKCS11 module", 0);
		return;
	}
	objval->initialised = 0;
	if (objval->initialised == 0) {
		zend_throw_exception(zend_ce_exception, "Already initialised PKCS11 module", 0);
		return;
	}

	CK_RV rv;
	CK_ULONG ulSlotCount;
	CK_SLOT_ID_PTR pSlotList;
	CK_SLOT_INFO slotInfo;

	void *pkcs11module = dlopen(module_path, RTLD_LAZY);
    CK_C_GetFunctionList C_GetFunctionList = dlsym(pkcs11module, "C_GetFunctionList");

    rv = C_GetFunctionList(&objval->functionList);
    assert(rv == CKR_OK);
	rv = objval->functionList->C_Initialize(NULL);
    assert(rv == CKR_OK);

    objval->initialised = 1;

	

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
    /*


	/**/
	dlclose(pkcs11module);
}
PHP_METHOD(Module, getInfo) {
	char *var;
	size_t var_len;
	zend_string *retval;
	CK_RV rv;
	CK_INFO info;

	pkcs11_object *objval = pkcs11_from_zend_object(Z_OBJ_P(getThis()));

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

static zend_function_entry module_class_functions[] = {
	PHP_ME(Module, __construct, arginfo_pkcs11_module___construct, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
	PHP_ME(Module, getInfo, arginfo_pkcs11_module_getInfo, ZEND_ACC_PUBLIC)
	PHP_FE_END
};

static zend_object* pkcs11_ctor(zend_class_entry *ce) {
    pkcs11_object *objval = zend_object_alloc(sizeof(pkcs11_object), ce);

    zend_object* ret = pkcs11_to_zend_object(objval);
    zend_object_std_init(ret, ce);
    object_properties_init(ret, ce);

    return ret;
}


static zend_class_entry *ce_Pkcs11_Module;
static zend_object_handlers pkcs11_handlers;

PHP_MINIT_FUNCTION(pkcs11)
{
	zend_class_entry ce;

	INIT_NS_CLASS_ENTRY(ce, "Pkcs11", "Module", module_class_functions);
	ce_Pkcs11_Module = zend_register_internal_class(&ce);

	memcpy(&pkcs11_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    pkcs11_handlers.offset = XtOffsetOf(pkcs11_object, std);

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
	"pkcs11",					/* Extension name */
	NULL,			/* zend_function_entry */
	PHP_MINIT(pkcs11),							/* PHP_MINIT - Module initialization */
	NULL,							/* PHP_MSHUTDOWN - Module shutdown */
	NULL,			/* PHP_RINIT - Request initialization */
	NULL,							/* PHP_RSHUTDOWN - Request shutdown */
	PHP_MINFO(pkcs11),			/* PHP_MINFO - Module info */
	PHP_PKCS11_VERSION,		/* Version */
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_PKCS11
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(pkcs11)
#endif
