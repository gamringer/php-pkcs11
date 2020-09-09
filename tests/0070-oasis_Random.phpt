--TEST--
OASIS Session Basic test - C_SeedRandom(), C_GenerateRandom()
--SKIPIF--
<?php
if (!extension_loaded('pkcs11')) {
  echo 'skip';
}

if (getenv('PHP11_MODULE') === false) {
  echo 'skip';
}

?>
--FILE--
<?php declare(strict_types=1);

$modulePath = getenv('PHP11_MODULE');
$module = new Pkcs11\Module($modulePath);

$rv = $module->C_GetSlotList(true, $s);
var_dump($rv);

$session = new Pkcs11\Session($module, $s[0], Pkcs11\CKF_SERIAL_SESSION); # aka C_OpenSession()

/* TODO: C_SeedRandom() */
$rv = $session->C_SeedRandom('1603soixantedix8');
if ($rv === Pkcs11\CKR_RANDOM_SEED_NOT_SUPPORTED)
  $rv = 0; # XXX fake, ignore any smart cards that do not support SeedRandom
var_dump($rv);

$rv = $session->C_GenerateRandom(64, $rand);
var_dump($rv);
printf("rand len=%d".PHP_EOL, strlen($rand));

?>
--EXPECTF--
int(0)
int(0)
int(0)
rand len=64
