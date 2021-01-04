--TEST--
Get information about cryptoki
--SKIPIF--
<?php

require_once 'require-module-load.skipif.inc';

?>
--FILE--
<?php

declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$info = $module->getInfo();
var_dump(sizeof($info, COUNT_RECURSIVE));

?>
--EXPECT--
int(8)
