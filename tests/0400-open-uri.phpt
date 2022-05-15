--TEST--
Find object and retrieve attributes
--SKIPIF--
<?php

require_once 'require-userpin-login.skipif.inc';

require_once 'require-create-object.skipif.inc';

?>
--FILE--
<?php

declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));

$session->generateKeyPair(new Pkcs11\Mechanism(Pkcs11\CKM_RSA_PKCS_KEY_PAIR_GEN), [
	Pkcs11\CKA_ENCRYPT => true,
	Pkcs11\CKA_MODULUS_BITS => 2048,
	Pkcs11\CKA_PUBLIC_EXPONENT => hex2bin('010001'),
	Pkcs11\CKA_LABEL => "testPkcs11Url",
	Pkcs11\CKA_ID => "testPkcs11UrlPublicId",
],[
	Pkcs11\CKA_TOKEN => false,
	Pkcs11\CKA_PRIVATE => true,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_DECRYPT => true,
	Pkcs11\CKA_LABEL => "testPkcs11Url",
	Pkcs11\CKA_ID => "testPkcs11UrlPrivateId",
]);

$doesNotExist = $session->openUri("pkcs11:object=testPkcs11Urlsdf;type=private;");
var_dump($doesNotExist);

$doesNotExist = $session->openUri("pkcs11:object=testPkcs11Url;type=data;");
var_dump($doesNotExist);

$both = $session->openUri("pkcs11:object=testPkcs11Url;");
var_dump($both);

$publicById = $session->openUri("pkcs11:id=testPkcs11UrlPublicId;");
var_dump($publicById);

$all = $session->openUri("pkcs11:");
var_dump($all);

$allPrivate = $session->openUri("pkcs11:type=private;");
var_dump($allPrivate);

$allSecret = $session->openUri("pkcs11:type=secret-key;");
var_dump($allSecret);

$privateKeySearchResult = $session->openUri("pkcs11:object=testPkcs11Url;type=private;");

$mechanism = new Pkcs11\Mechanism(Pkcs11\CKM_SHA256_RSA_PKCS);

$data = "Hello World!";
$signature = $privateKeySearchResult[0]->sign($mechanism, $data);
var_dump(bin2hex($signature));

$publicKeySearchResult = $session->openUri("pkcs11:object=testPkcs11Url;type=public");
$valid = $publicKeySearchResult[0]->verify($mechanism, $data, $signature);
var_dump($valid);

$session->logout();


?>
--EXPECTF--
array(0) {
}
array(0) {
}
array(2) {
  [0]=>
  object(Pkcs11\Key)#6 (0) {
  }
  [1]=>
  object(Pkcs11\Key)#3 (0) {
  }
}
array(1) {
  [0]=>
  object(Pkcs11\Key)#7 (0) {
  }
}
array(5) {
  [0]=>
  object(Pkcs11\Key)#8 (0) {
  }
  [1]=>
  object(Pkcs11\Key)#9 (0) {
  }
  [2]=>
  object(Pkcs11\Key)#10 (0) {
  }
  [3]=>
  object(Pkcs11\Key)#11 (0) {
  }
  [4]=>
  object(Pkcs11\Key)#12 (0) {
  }
}
array(2) {
  [0]=>
  object(Pkcs11\Key)#13 (0) {
  }
  [1]=>
  object(Pkcs11\Key)#14 (0) {
  }
}
array(1) {
  [0]=>
  object(Pkcs11\Key)#15 (0) {
  }
}
string(512) "%x"
bool(true)
