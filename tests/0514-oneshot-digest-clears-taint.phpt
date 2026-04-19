--TEST--
One-shot Session::digest() clears taint on success; session is returned to pool on destroy
--SKIPIF--
<?php
require_once 'require-userpin-login.skipif.inc';
if (!in_array(Pkcs11\CKM_SHA256, $module->getMechanismList((int)getenv('PHP11_SLOT')))) {
    echo 'skip: CKM_SHA256 not supported';
}
?>
--FILE--
<?php
declare(strict_types=1);

$module  = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));

// One-shot digest: C_DigestInit sets tainted=true, then successful C_Digest clears it.
$digest = $session->digest(new Pkcs11\Mechanism(Pkcs11\CKM_SHA256), 'Hello World!');
var_dump(bin2hex($digest));

// Destroy session without explicit logout — taint was cleared, so the session
// destructor should return it to the pool (C_Logout + in_use=false).
unset($session);

// Verify pool is intact: new openSession must succeed and return a clean session.
$session2 = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session2->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));

$info = $session2->getInfo();
var_dump(isset($info['state']));

$session2->logout();
echo "OK\n";
?>
--EXPECT--
string(64) "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
bool(true)
OK
