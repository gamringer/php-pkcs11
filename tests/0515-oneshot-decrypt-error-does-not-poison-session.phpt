--TEST--
Failed one-shot Key::decrypt() (bad GCM auth tag) does not poison later session use
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

$ciphertext = $key->encrypt($mechanism, 'Hello World!');
$bad = substr($ciphertext, 0, -16) . str_repeat("\xff", 16);

try {
    $key->decrypt($mechanism, $bad);
    echo "FAIL: expected exception\n";
} catch (\Pkcs11\Exception $e) {
    echo "caught\n";
}

unset($key);
unset($session);

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
