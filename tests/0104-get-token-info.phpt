--TEST--
OASIS C_GetTokenInfo() Basic test
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

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));

$tokenInfo = $module->getTokenInfo((int)getenv('PHP11_SLOT'));
var_dump(sizeof($tokenInfo, COUNT_RECURSIVE));

?>
--EXPECTF--
int(22)
