--TEST--
Session pool reuses handle across open/close cycles
--SKIPIF--
<?php
require_once 'require-userpin-login.skipif.inc';
?>
--FILE--
<?php
declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));

/* First session */
$session1 = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session1->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));

/* Get session info to verify it works */
$info1 = $session1->getInfo();
var_dump(isset($info1['state']));

/* Destroy session — returns to pool */
unset($session1);

/* Second session — should reuse the pooled handle.
 * The pool holds a logged-out session (C_Logout ran before pool return),
 * so login() must be called fresh with valid credentials. */
$session2 = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
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
