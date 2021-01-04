--TEST--
OASIS C_GetTokenInfo() Basic test
--SKIPIF--
<?php

require_once 'require-module-load.skipif.inc';

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
