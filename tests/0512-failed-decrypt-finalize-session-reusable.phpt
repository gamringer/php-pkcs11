--TEST--
Failed DecryptionContext::finalize() (bad GCM auth tag) does not crash; session is reusable
--SKIPIF--
<?php
require_once 'require-userpin-login.skipif.inc';
if (!in_array(Pkcs11\CKM_AES_GCM, $module->getMechanismList((int)getenv('PHP11_SLOT')))) {
    echo 'skip: CKM_AES_GCM not supported';
}
?>
--FILE--
<?php
declare(strict_types=1);

$module  = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));

$key = $session->generateKey(new Pkcs11\Mechanism(Pkcs11\CKM_AES_KEY_GEN), [
    Pkcs11\CKA_CLASS     => Pkcs11\CKO_SECRET_KEY,
    Pkcs11\CKA_VALUE_LEN => 32,
    Pkcs11\CKA_TOKEN     => false,
]);

$iv        = str_repeat("\x00", 16);
$gcmParams = new Pkcs11\GcmParams($iv, '', 128);
$mechanism = new Pkcs11\Mechanism(Pkcs11\CKM_AES_GCM, $gcmParams);

// Encrypt to obtain valid ciphertext || 16-byte GCM authentication tag.
$ciphertext = $key->encrypt($mechanism, 'Hello World!');

// Replace the auth tag with 0xff bytes to force authentication failure.
$bad = substr($ciphertext, 0, -16) . str_repeat("\xff", 16);

// initializeDecryption calls C_DecryptInit, which sets tainted = true.
$ctx = $key->initializeDecryption($mechanism);
$ctx->update($bad);          // GCM buffers data; auth tag not yet checked

try {
    $ctx->finalize();        // C_DecryptFinal: auth tag check fails here
    echo "FAIL: expected exception\n";
} catch (\Pkcs11\Exception $e) {
    echo "caught\n";
}

unset($ctx);
unset($key);
unset($session);

// Either the pool entry was reused or a fresh session was opened; both must work.
$session2 = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session2->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));

$info = $session2->getInfo();
var_dump(isset($info['state']));

$session2->logout();
echo "OK\n";
?>
--EXPECT--
caught
bool(true)
OK
