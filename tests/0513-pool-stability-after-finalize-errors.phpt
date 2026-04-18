--TEST--
Session pool is not exhausted after five consecutive DecryptionContext::finalize() failures
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

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));

$iv        = str_repeat("\x00", 16);
$gcmParams = new Pkcs11\GcmParams($iv, '', 128);
$mechanism = new Pkcs11\Mechanism(Pkcs11\CKM_AES_GCM, $gcmParams);

for ($i = 0; $i < 5; $i++) {
    $session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
    $session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));

    $key = $session->generateKey(new Pkcs11\Mechanism(Pkcs11\CKM_AES_KEY_GEN), [
        Pkcs11\CKA_CLASS     => Pkcs11\CKO_SECRET_KEY,
        Pkcs11\CKA_VALUE_LEN => 32,
        Pkcs11\CKA_TOKEN     => false,
    ]);

    $ciphertext = $key->encrypt($mechanism, 'Hello World!');
    $bad = substr($ciphertext, 0, -16) . str_repeat("\xff", 16);

    $ctx = $key->initializeDecryption($mechanism);
    $ctx->update($bad);
    try {
        $ctx->finalize();
    } catch (\Pkcs11\Exception $e) {
        // expected: auth tag mismatch
    }

    unset($ctx);
    unset($key);
    unset($session);

    // Each iteration must be able to open a fresh, functional session.
    $check = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
    $check->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));
    $info = $check->getInfo();
    if (!isset($info['state'])) {
        echo "FAIL at iteration $i\n";
        exit(1);
    }
    $check->logout();
    unset($check);
}

echo "OK\n";
?>
--EXPECT--
OK
