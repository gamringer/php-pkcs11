--TEST--
Wrong credentials are always rejected, including on pooled sessions
--SKIPIF--
<?php
require_once 'require-userpin-login.skipif.inc';
?>
--FILE--
<?php
declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));

/* Wrong PIN on a fresh session must throw */
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
try {
    $session->login(Pkcs11\CKU_USER, 'wrongpassword');
    echo "FAIL: expected exception\n";
} catch (\Exception $e) {
    echo "fresh session: wrong pin rejected\n";
}

/* Correct PIN must work */
$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));
echo "fresh session: correct pin accepted\n";
$session->logout();

/* Pool the session (C_Logout ran before pool return) */
unset($session);

/* Get the pooled session back */
$session2 = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);

/* Wrong PIN on pooled session must also throw */
try {
    $session2->login(Pkcs11\CKU_USER, 'wrongpassword');
    echo "FAIL: expected exception on pooled session\n";
} catch (\Exception $e) {
    echo "pooled session: wrong pin rejected\n";
}

/* Correct PIN on pooled session must work */
$session2->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));
echo "pooled session: correct pin accepted\n";
$session2->logout();
?>
--EXPECT--
fresh session: wrong pin rejected
fresh session: correct pin accepted
pooled session: wrong pin rejected
pooled session: correct pin accepted
