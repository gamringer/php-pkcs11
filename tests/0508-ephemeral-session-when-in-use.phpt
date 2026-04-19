--TEST--
Second openSession on an in-use pool key returns an ephemeral session
--SKIPIF--
<?php
require_once 'require-userpin-login.skipif.inc';
?>
--FILE--
<?php
declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));

/* Session 1 — takes the pool entry */
$session1 = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session1->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));

/* Session 2 — same slot+flags, but pool entry is in_use → must be ephemeral.
 * The token is already authenticated via session1, so login() must not be
 * called again (C_Login would return CKR_USER_ALREADY_LOGGED_IN). */
$session2 = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);

$info1 = $session1->getInfo();
$info2 = $session2->getInfo();
var_dump(isset($info1['state']));
var_dump(isset($info2['state']));

/* Logout via session1 (token-level). Destroy both. */
$session1->logout();
unset($session1);
unset($session2);

$session3 = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session3->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));
$info3 = $session3->getInfo();
var_dump(isset($info3['state']));
$session3->logout();
echo "OK\n";
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
OK
