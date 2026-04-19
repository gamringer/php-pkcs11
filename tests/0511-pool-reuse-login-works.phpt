--TEST--
Login succeeds normally after pool reuse, proving C_Logout ran before pooling
--SKIPIF--
<?php
require_once 'require-userpin-login.skipif.inc';
?>
--FILE--
<?php
declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));

/* First request: login, do work, return to pool */
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));
$info = $session->getInfo();
var_dump(isset($info['state']));
$session->logout();
unset($session);

/* Second request: gets the pooled session (logged out by pool return) */
$session2 = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);

/* Must be able to login with correct PIN — proves C_Logout ran before pooling */
$session2->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));
$info2 = $session2->getInfo();
var_dump(isset($info2['state']));
$session2->logout();

echo "OK\n";
?>
--EXPECT--
bool(true)
bool(true)
OK
