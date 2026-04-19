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

/* --- Phase 2: persistent connections --- */

typedef struct _pkcs11_lib_record {
    void                *dlhandle;
    CK_FUNCTION_LIST_PTR functionList;
    volatile bool        finalized;  /* set by MSHUTDOWN before C_Finalize */
} pkcs11_lib_record;

typedef struct _pkcs11_pooled_session {
    CK_SESSION_HANDLE   handle;
    pkcs11_lib_record  *lib;      /* for C_CloseSession + finalized check in dtor */
    bool                in_use;   /* true = owned by a live PHP Session object */
    bool                dead;     /* true = handle already closed / stale */
} pkcs11_pooled_session;

ZEND_BEGIN_MODULE_GLOBALS(pkcs11)
    HashTable session_pool;  /* key: "realpath:slotID:flags" -> pkcs11_pooled_session* */
ZEND_END_MODULE_GLOBALS(pkcs11)

#ifdef ZTS
# define PKCS11_G(v) ZEND_TSRMG(pkcs11_globals_id, zend_pkcs11_globals *, v)
#else
# define PKCS11_G(v) (pkcs11_globals.v)
#endif

ZEND_EXTERN_MODULE_GLOBALS(pkcs11)

/* Process-wide library registry lock/unlock macros */
extern pthread_mutex_t pkcs11_lib_mutex;
#ifdef ZTS
# define PKCS11_LIB_LOCK()   pthread_mutex_lock(&pkcs11_lib_mutex)
# define PKCS11_LIB_UNLOCK() pthread_mutex_unlock(&pkcs11_lib_mutex)
#else
# define PKCS11_LIB_LOCK()   do { } while(0)
# define PKCS11_LIB_UNLOCK() do { } while(0)
#endif

#endif	/* PHP_PKCS11_H */
