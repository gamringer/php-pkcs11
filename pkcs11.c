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

PHP_METHOD(Module, __construct) {
	char *module_path;
	size_t module_path_len;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_PATH(module_path, module_path_len)
	ZEND_PARSE_PARAMETERS_END();

	CK_RV rv;
	CK_INFO info;
	CK_ULONG ulSlotCount;
	CK_SLOT_ID_PTR pSlotList;
	CK_SLOT_INFO slotInfo;

	void *pkcs11module = dlopen(module_path, RTLD_LAZY);
    CK_C_GetFunctionList C_GetFunctionList = dlsym(pkcs11module, "C_GetFunctionList");

    CK_FUNCTION_LIST_PTR pFunctionList;
    rv = C_GetFunctionList(&pFunctionList);
    assert(rv == CKR_OK);

	pFunctionList->C_Initialize(NULL);
	pFunctionList->C_GetInfo(&info);

	if (info.cryptokiVersion.major == 2) {
		printf("Is version 2\n");
	} else {
		printf("Is _not_ version 2\n");
	}
	rv = pFunctionList->C_GetSlotList(CK_FALSE, NULL_PTR, &ulSlotCount);
	assert(rv == CKR_OK);

	pSlotList = (CK_SLOT_ID_PTR) malloc(ulSlotCount * sizeof(CK_SLOT_ID));
	rv = pFunctionList->C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
	assert(rv == CKR_OK);

	uint i;
	for (i=0; i<ulSlotCount; i++) {
		printf("%d \n", i);
		rv = pFunctionList->C_GetSlotInfo(pSlotList[i], &slotInfo);
		assert(rv == CKR_OK);
		printf("%s\n", slotInfo.slotDescription);
	}

	dlclose(pkcs11module);
}
PHP_METHOD(Module, foo) {
	char *var;
	size_t var_len;
	zend_string *retval;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STRING(var, var_len)
	ZEND_PARSE_PARAMETERS_END();

	retval = strpprintf(0, "Hello %s", var);

	RETURN_STR(retval);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_module___construct, 0, 0, 1)
	ZEND_ARG_TYPE_INFO(0, module_path, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_pkcs11_module_foo, 0, 0, 1)
	ZEND_ARG_TYPE_INFO(0, var, IS_STRING, 0)
ZEND_END_ARG_INFO()

static zend_function_entry module_class_functions[] = {
	PHP_ME(Module, __construct, arginfo_pkcs11_module___construct, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
	PHP_ME(Module, foo, arginfo_pkcs11_module_foo, ZEND_ACC_PUBLIC)
	PHP_FE_END
};

zend_class_entry *ce_Pkcs11_Module;

PHP_MINIT_FUNCTION(pkcs11)
{
	zend_class_entry ce;

	INIT_NS_CLASS_ENTRY(ce, "Pkcs11", "Module", module_class_functions);
	ce_Pkcs11_Module = zend_register_internal_class(&ce);

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
