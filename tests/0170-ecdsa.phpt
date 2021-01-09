--TEST--
Sign/Verify using ECDSA P-384
--SKIPIF--
<?php

require_once 'require-userpin-login.skipif.inc';

if (!in_array(Pkcs11\CKM_ECDSA, $module->getMechanismList((int)getenv('PHP11_SLOT')))) {
	echo 'skip: CKM_ECDSA not supported ';
}

?>
--FILE--
<?php

declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));

$domainParameters = hex2bin('06082A8648CE3D030107');

$keypair = $session->generateKeyPair(new Pkcs11\Mechanism(Pkcs11\CKM_EC_KEY_PAIR_GEN), [
	Pkcs11\CKA_VERIFY => true,
	Pkcs11\CKA_LABEL => "Test ECDSA Public",
	Pkcs11\CKA_EC_PARAMS => $domainParameters,
],[
	Pkcs11\CKA_TOKEN => false,
	Pkcs11\CKA_PRIVATE => true,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_SIGN => true,
	Pkcs11\CKA_LABEL => "Test ECDSA Private",
]);

$attributes = $keypair->pkey->getAttributeValue([
	Pkcs11\CKA_LABEL,
	Pkcs11\CKA_EC_POINT,
]);

$data = "Hello World!";
$hash = hash('sha256', $data, true);
$mechanism = new Pkcs11\Mechanism(Pkcs11\CKM_ECDSA);
$signature = $keypair->skey->sign($mechanism, $hash);
$check = $keypair->pkey->verify($mechanism, $hash, $signature);

$session->logout();

var_dump(bin2hex($data));
var_dump(bin2hex($signature));
var_dump(bin2hex(substr($signature,  0, 32)));
var_dump(bin2hex(substr($signature, 32, 32)));
echo 'Validates: ' . ($check ? 'Yes' : 'No'), PHP_EOL;

?>
--EXPECTF--
string(24) "48656c6c6f20576f726c6421"
string(128) "%x"
string(64) "%x"
string(64) "%x"
Validates: Yes
