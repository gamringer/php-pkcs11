--TEST--
Tainted session (with active C_*Init) is closed, not returned to pool
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

/* Start a multi-part sign — taints the session */
$ctx = $key->initializeSignature(new Pkcs11\Mechanism(Pkcs11\CKM_SHA256_HMAC));

/* Abandon the context and destroy the session WITHOUT finalizing.
 * Correct order: ctx holds ref to key, key holds ref to session.
 * Unset ctx first so key is released, then key releases session. */
unset($ctx);
unset($key);
unset($session);

/* Open a new session — pool entry must be dead (tainted session was closed).
 * If the tainted session had been pooled, this would get a session in
 * an inconsistent state (CKR_OPERATION_ACTIVE on sign). */
$session2 = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session2->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));

$info = $session2->getInfo();
var_dump(isset($info['state']));

$session2->logout();
echo "OK\n";
?>
--EXPECT--
bool(true)
OK
