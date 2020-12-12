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

// var_dump($Attributes);
// var_dump($AttributesInfo);

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

foreach($o as $handle) {
  unset($Attributes['Object']); /* avoid unsupported contents by parseTemplate() */
  printf("dump object %d: ", $handle);
  $rv = $module->C_GetAttributeValue($session, $handle, $Attributes);
  switch($rv) {
    case Pkcs11\CKR_OK:
      printf("Pkcs11\CKR_OK %d".PHP_EOL, $rv);
      printf("dump DONE".PHP_EOL);
      // break 1;
      continue 2;
    case Pkcs11\CKR_ATTRIBUTE_SENSITIVE:
      printf("Pkcs11\CKR_ATTRIBUTE_SENSITIVE %d".PHP_EOL, $rv);
      printf("dump DONE".PHP_EOL);
      // break 1;
      continue 2;
    case Pkcs11\CKR_ATTRIBUTE_TYPE_INVALID:
      printf("Pkcs11\CKR_ATTRIBUTE_TYPE_INVALID %d".PHP_EOL, $rv);
      printf("dump DONE".PHP_EOL);
      // break 1;
      continue 2;
    case Pkcs11\CKR_BUFFER_TOO_SMALL:
      printf("Pkcs11\CKR_BUFFER_TOO_SMALL %d".PHP_EOL, $rv);
      printf("dump DONE".PHP_EOL);
      // break 1;
      continue 2;
    default:
      printf("error %d", $rv);
      break 1;
  }
  // var_dump($Attributes['Object']);
  foreach($Attributes['Object'] as $v) {
    printf("%s : %s".PHP_EOL, $AttributesInfo[$v['type']], $v['Value']);
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
dump object 1: %s %d
dump DONE
%A
dump DONE
int(0)
int(0)
OK
