/*
   +----------------------------------------------------------------------+
   | PHP PKCS11                                                           |
   +----------------------------------------------------------------------+
   | Copyright (c) Guillaume Amringer                                     |
   +----------------------------------------------------------------------+
   | This source file is subject to the MIT license, that is bundled with |
   | this package in the file LICENSE, and is available through the at    |
   | the following url: https://mit-license.org/                          |
   +----------------------------------------------------------------------+
   | Author: Guillaume Amringer                                           |
   +----------------------------------------------------------------------+
*/

#include "pkcs11int.h"

zend_class_entry *ce_Pkcs11_KeyPair;
static zend_object_handlers pkcs11_keypair_handlers;


void pkcs11_keypair_shutdown(pkcs11_keypair_object *obj) {
}

static zend_function_entry keypair_class_functions[] = {
    PHP_FE_END
};


DEFINE_MAGIC_FUNCS(pkcs11_keypair, keypair, KeyPair)
