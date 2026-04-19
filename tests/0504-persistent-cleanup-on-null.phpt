--TEST--
Unsetting module and session does not crash; subsequent operations work
--SKIPIF--
<?php
require_once 'require-userpin-login.skipif.inc';
?>
--FILE--
<?php
declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));

/* Force GC of session then module */
$session = null;
$module = null;

/* Re-create — should work cleanly */
$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));

$info = $session->getInfo();
var_dump(isset($info['state']));

$session->logout();
echo "OK\n";
?>
--EXPECT--
bool(true)
OK
