--TEST--
Get Mechanism List & Info
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

?>
--FILE--
<?php

declare(strict_types=1);

/* build a list of mechanism that the card may support */
$c = get_defined_constants(TRUE)['pkcs11'];
foreach($c as $k => $v) {
    if (strpos($k, 'CKM_') === FALSE)
        continue;
    if ($k === 'Pkcs11\CKM_VENDOR_DEFINED')
        continue;
    $ckm[$v] = $k;
}

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));

$alg = $module->getMechanismList((int)getenv('PHP11_SLOT'));

printf("PKCS11 supported algorithms:".PHP_EOL);
foreach($alg as $k => $t) {
    printf("%s".PHP_EOL, $ckm[$t]);
    $mechanismInfo = $module->getMechanismInfo($s[0], $t);
    print_r($mechanismInfo);
}

?>
--EXPECTF--
PKCS11 supported algorithms:
%A
