--TEST--
OASIS C_GetMechanismList(), C_GetMechanismInfo() Basic test
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

/* build a list of mechanism that the card may support */
$c = get_defined_constants(TRUE)['pkcs11'];
foreach($c as $k => $v) {
  if (strpos($k, 'CKM_') === FALSE)
    continue;
  if ($k === 'Pkcs11\CKM_VENDOR_DEFINED')
    continue;
  $ckm[$v] = $k;
}

$modulePath = getenv('PHP11_MODULE');
$module = new Pkcs11\Module($modulePath);

$rv = $module->C_GetSlotList(true, $s);
var_dump($rv);

$rv = $module->C_GetMechanismList($s[0], $alg);
var_dump($rv);
printf("PKCS11 supported algorithms:".PHP_EOL);
foreach($alg as $k => $t) {
  printf("%s".PHP_EOL, $ckm[$t]);
  $rv = $module->C_GetMechanismInfo($s[0], $t, $mechanismInfo);
  print_r($mechanismInfo);
}

?>
--EXPECTF--
int(0)
int(0)
PKCS11 supported algorithms:
%A
