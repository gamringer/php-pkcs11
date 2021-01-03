--TEST--
Open Session
--SKIPIF--
<?php

if (!extension_loaded('pkcs11')) {
    echo 'skip';
}

if (getenv('PHP11_MODULE') === false) {
    echo 'skip';
}

if (getenv('PHP11_SLOT') === false) {
    echo 'skip';
}

try {
    $module = new Pkcs11\Module(getenv('PHP11_MODULE'));
} catch (\Throwable $e) {
    echo 'skip';
}

?>
--FILE--
<?php

declare(strict_types=1);


$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
var_dump($session->getInfo());

$session2 = $module->openSession((int)getenv('PHP11_SLOT'));
var_dump($session2->getInfo());

?>
--EXPECTF--
array(4) {
  ["slotID"]=>
  int(%d)
  ["state"]=>
  int(2)
  ["flags"]=>
  int(6)
  ["ulDeviceError"]=>
  int(0)
}
array(4) {
  ["slotID"]=>
  int(%d)
  ["state"]=>
  int(0)
  ["flags"]=>
  int(4)
  ["ulDeviceError"]=>
  int(0)
}