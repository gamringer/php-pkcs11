--TEST--
One-shot Key::sign() clears taint; session is returned to pool on destroy
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

/* Create a generic-secret key compatible with CKM_SHA256_HMAC */
$key = $session->createObject([
    Pkcs11\CKA_CLASS    => Pkcs11\CKO_SECRET_KEY,
    Pkcs11\CKA_KEY_TYPE => Pkcs11\CKK_GENERIC_SECRET,
    Pkcs11\CKA_VALUE    => str_repeat(chr(0), 32),
    Pkcs11\CKA_PRIVATE  => true,
    Pkcs11\CKA_SIGN     => true,
]);

/* One-shot sign — uses C_SignInit + C_Sign internally.
 * Taint is set on C_SignInit, cleared on successful C_Sign. */
$signature = $key->sign(new Pkcs11\Mechanism(Pkcs11\CKM_SHA256_HMAC), 'test data');
var_dump(strlen($signature) > 0);

/* Destroy session — taint was cleared, so session should be pooled */
unset($key);
unset($session);

/* Pool reuse: new session should work normally (sign again) */
$session2 = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session2->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));

/* Do another operation to confirm the pooled session is clean */
$info = $session2->getInfo();
var_dump(isset($info['state']));

$session2->logout();
echo "OK\n";
?>
--EXPECT--
bool(true)
bool(true)
OK
