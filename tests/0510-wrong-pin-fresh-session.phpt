--TEST--
Wrong PIN on a fresh non-pooled session always throws
--SKIPIF--
<?php
require_once 'require-userpin-login.skipif.inc';
?>
--FILE--
<?php
declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);

try {
    $session->login(Pkcs11\CKU_USER, 'definitelyWrongPin!');
    echo "FAIL: expected Pkcs11 exception\n";
} catch (\Exception $e) {
    echo "wrong pin rejected\n";
}

/* Correct PIN still works on the same (now fresh) session */
$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));
echo "correct pin accepted\n";
$session->logout();
?>
--EXPECT--
wrong pin rejected
correct pin accepted
