--TEST--
Get information about cryptoki
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
<?php

declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$info = $module->getInfo();
var_dump(sizeof($info, COUNT_RECURSIVE));

?>
--EXPECT--
int(8)
