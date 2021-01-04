--TEST--
Copy object and retrieve attributes
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

$object = $session->createObject([
	Pkcs11\CKA_CLASS => Pkcs11\CKO_DATA,
	Pkcs11\CKA_APPLICATION => "Some App",
	Pkcs11\CKA_VALUE => 'Hello World!',
	Pkcs11\CKA_LABEL => "Original Label",
]);
var_dump($object);

$copy = $session->copyObject($object, [
	Pkcs11\CKA_LABEL => "New Label",
]);

var_dump($copy);

$attributes = $copy->getAttributeValue([
	Pkcs11\CKA_VALUE,
	Pkcs11\CKA_LABEL,
]);

var_dump($attributes);

$session->logout();

?>
--EXPECTF--
object(Pkcs11\P11Object)#%d (0) {
}
object(Pkcs11\P11Object)#%d (0) {
}
array(2) {
  [17]=>
  string(12) "Hello World!"
  [3]=>
  string(9) "New Label"
}