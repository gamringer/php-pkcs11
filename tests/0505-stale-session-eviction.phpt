--TEST--
Dead pool entry is skipped; fresh session is opened
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

/* Externally close the session via OASIS method — marks pool entry dead */
$module->C_CloseSession($session);

/* Destroy the PHP session object */
unset($session);

/* Re-open — the dead pool entry must be skipped; a fresh session is opened */
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
