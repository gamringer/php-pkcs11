dnl config.m4 for extension pkcs11

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary.

dnl If your extension references something external, use 'with':

dnl PHP_ARG_WITH([pkcs11],
dnl   [for pkcs11 support],
dnl   [AS_HELP_STRING([--with-pkcs11],
dnl     [Include pkcs11 support])])

dnl Otherwise use 'enable':

PHP_ARG_ENABLE([pkcs11],
  [whether to enable pkcs11 support],
  [AS_HELP_STRING([--enable-pkcs11],
    [Enable pkcs11 support])],
  [no])

if test "$PHP_PKCS11" != "no"; then

  dnl Write more examples of tests here...

  dnl Remove this code block if the library does not support pkg-config.
  dnl PKG_CHECK_MODULES([LIBFOO], [foo])
  dnl PHP_EVAL_INCLINE($LIBFOO_CFLAGS)
  dnl PHP_EVAL_LIBLINE($LIBFOO_LIBS, PKCS11_SHARED_LIBADD)

  dnl If you need to check for a particular library version using PKG_CHECK_MODULES,
  dnl you can use comparison operators. For example:
  dnl PKG_CHECK_MODULES([LIBFOO], [foo >= 1.2.3])
  dnl PKG_CHECK_MODULES([LIBFOO], [foo < 3.4])
  dnl PKG_CHECK_MODULES([LIBFOO], [foo = 1.2.3])

  dnl Remove this code block if the library supports pkg-config.
  dnl --with-pkcs11 -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/pkcs11.h"  # you most likely want to change this
  dnl if test -r $PHP_PKCS11/$SEARCH_FOR; then # path given as parameter
  dnl   PKCS11_DIR=$PHP_PKCS11
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for pkcs11 files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       PKCS11_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$PKCS11_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the pkcs11 distribution])
  dnl fi

  dnl Remove this code block if the library supports pkg-config.
  dnl --with-pkcs11 -> add include path
  dnl PHP_ADD_INCLUDE($PKCS11_DIR/include)

  dnl Remove this code block if the library supports pkg-config.
  dnl --with-pkcs11 -> check for lib and symbol presence
  dnl LIBNAME=PKCS11 # you may want to change this
  dnl LIBSYMBOL=PKCS11 # you most likely want to change this

  dnl If you need to check for a particular library function (e.g. a conditional
  dnl or version-dependent feature) and you are using pkg-config:
  dnl PHP_CHECK_LIBRARY($LIBNAME, $LIBSYMBOL,
  dnl [
  dnl   AC_DEFINE(HAVE_PKCS11_FEATURE, 1, [ ])
  dnl ],[
  dnl   AC_MSG_ERROR([FEATURE not supported by your pkcs11 library.])
  dnl ], [
  dnl   $LIBFOO_LIBS
  dnl ])

  dnl If you need to check for a particular library function (e.g. a conditional
  dnl or version-dependent feature) and you are not using pkg-config:
  dnl PHP_CHECK_LIBRARY($LIBNAME, $LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $PKCS11_DIR/$PHP_LIBDIR, PKCS11_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_PKCS11_FEATURE, 1, [ ])
  dnl ],[
  dnl   AC_MSG_ERROR([FEATURE not supported by your pkcs11 library.])
  dnl ],[
  dnl   -L$PKCS11_DIR/$PHP_LIBDIR -lm
  dnl ])
  dnl
  dnl PHP_SUBST(PKCS11_SHARED_LIBADD)

  dnl In case of no dependencies
  AC_DEFINE(HAVE_PKCS11, 1, [ Have pkcs11 support ])

  PHP_NEW_EXTENSION(pkcs11, pkcs11.c pkcs11object.c pkcs11key.c pkcs11keypair.c pkcs11module.c pkcs11signaturecontext.c pkcs11verificationcontext.c pkcs11digestcontext.c pkcs11encryptioncontext.c pkcs11decryptioncontext.c pkcs11mechanism.c pkcs11rsapssparams.c pkcs11rsaoaepparams.c pkcs11gcmparams.c pkcs11chacha20params.c pkcs11salsa20params.c pkcs11salsa20chacha20poly1305params.c pkcs11ecdh1deriveparams.c pkcs11session.c, $ext_shared)
fi
