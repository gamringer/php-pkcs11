--TEST--
OASIS C_GetAttributeValue(): fetch all
--SKIPIF--
<?php
if (!extension_loaded('pkcs11')) {
  echo 'skip';
}

if (getenv('PHP11_MODULE') === false) {
  echo 'skip';
}

if (getenv('PHP11_PIN') === false) {
  echo 'skip';
}
?>
--FILE--
<?php declare(strict_types=1);

$verbose = false;

/* Initialize the list of attribtues */
$c = get_defined_constants(TRUE)['pkcs11'];
$Attributes = array();
$AttributesInfo = array();
foreach($c as $k => $v) {
  if ($k === 'Pkcs11\CKA_VENDOR_DEFINED')
    continue;
  if (strpos($k, 'Pkcs11\CKA_') !== FALSE) {
    $Attributes[$v] = null;
    $AttributesInfo[$v] = $k; /* commented/stringified entries */
  }
}

if ($verbose) var_dump($Attributes);
if ($verbose) var_dump($AttributesInfo);

$modulePath = getenv('PHP11_MODULE');
$module = new Pkcs11\Module($modulePath);

$rv = $module->C_GetSlotList(true, $s);
var_dump($rv);

$rv = $module->C_OpenSession($s[0], Pkcs11\CKF_SERIAL_SESSION, null, null, $session);
var_dump($rv);
var_dump($session);

$rv = $module->C_GetSessionInfo($session, $pInfo);
var_dump($rv);

if ($session->getInfo() !== $pInfo) {
  printf("Error getInfo() vs C_GetSessionInfo()".PHP_EOL);
  print_r($session->getInfo());
  print_r($pInfo);
}

$pin = getenv('PHP11_PIN');
if (strlen($pin) === 0)
  $pin = null; # Smart card without any pin code

$rv = $module->C_Login($session, Pkcs11\CKU_USER, $pin);
var_dump($rv);

$rv = $module->C_FindObjectsInit($session);
var_dump($rv);

$rv = $module->C_FindObjects($session, $o);
var_dump($rv);
var_dump(count($o));

/*
 * Oasis' C_GetAttributeValue() will fill the return'd values
 * into the same array as the input list, so we need to clone
 * the content in order to reuse them for each iteration
 * of the loop.
 */
function AttributeClone(array $Attributes): array {
  $r = array();

  foreach($Attributes as $k => $v) {
    $r[$k] = $v;
  }

  return $r;
}

foreach($o as $handle) {
  $Values = AttributeClone($Attributes);
  printf("dump object %d: ", $handle);
  $rv = $module->C_GetAttributeValue($session, $handle, $Values);
  switch($rv) {
    case Pkcs11\CKR_OK:
      printf("Pkcs11\CKR_OK %d".PHP_EOL, $rv);
      printf("dump DONE".PHP_EOL);
      if ($verbose) break 1;
      continue 2;
    case Pkcs11\CKR_ATTRIBUTE_SENSITIVE:
      printf("Pkcs11\CKR_ATTRIBUTE_SENSITIVE %d".PHP_EOL, $rv);
      printf("dump DONE".PHP_EOL);
      if ($verbose) break 1;
      continue 2;
    case Pkcs11\CKR_ATTRIBUTE_TYPE_INVALID:
      printf("Pkcs11\CKR_ATTRIBUTE_TYPE_INVALID %d".PHP_EOL, $rv);
      printf("dump DONE".PHP_EOL);
      if ($verbose) break 1;
      continue 2;
    case Pkcs11\CKR_BUFFER_TOO_SMALL:
      printf("Pkcs11\CKR_BUFFER_TOO_SMALL %d".PHP_EOL, $rv);
      printf("dump DONE".PHP_EOL);
      if ($verbose) break 1;
      continue 2;
    default:
      printf("error %d", $rv);
      break 1;
  }
  if ($verbose) {
    foreach($Values as $t => $v)
      printf("%s : (%d)%s".PHP_EOL, $AttributesInfo[$t], strlen($v ?? ''), $v);
  }
  printf(PHP_EOL);
}

$rv = $module->C_FindObjectsFinal($session);
var_dump($rv);

$rv = $module->C_Logout($session);
var_dump($rv);

$rv = $module->C_CloseSession($session);
// or use unset($session); # aka C_CloseSession()

printf("OK".PHP_EOL);

?>
--EXPECTF--
int(0)
int(0)
object(Pkcs11\Session)#2 (2) {
  ["hSession"]=>
  int(1)
  ["slotID"]=>
  int(%d)
}
int(0)
int(0)
int(0)
int(0)
int(%d)
%A
OK
