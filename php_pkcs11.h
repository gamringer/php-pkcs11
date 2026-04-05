/*
   +----------------------------------------------------------------------+
   | PHP PKCS11                                                           |
   +----------------------------------------------------------------------+
   | Copyright (c) Guillaume Amringer                                     |
   +----------------------------------------------------------------------+
   | This source file is subject to the MIT license, that is bundled with |
   | this package in the file LICENSE, and is available at the following  |
   | url: https://mit-license.org/                                        |
   +----------------------------------------------------------------------+
   | Author: Guillaume Amringer                                           |
   +----------------------------------------------------------------------+
*/

#ifndef PHP_PKCS11_H
# define PHP_PKCS11_H

extern zend_module_entry pkcs11_module_entry;
# define phpext_pkcs11_ptr &pkcs11_module_entry

# define PHP_PKCS11_NAME    "pkcs11"
# define PHP_PKCS11_VERSION "1.1.3"

# if defined(ZTS) && defined(COMPILE_DL_PKCS11)
ZEND_TSRMLS_CACHE_EXTERN()
# endif

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "oasis/pkcs11.h"

#endif	/* PHP_PKCS11_H */
