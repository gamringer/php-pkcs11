--TEST--
Check if pkcs11 is loaded
--SKIPIF--
<?php
if (!extension_loaded('pkcs11')) {
	echo 'skip';
}
?>
--FILE--
<?php declare(strict_types=1);
echo 'Extension "pkcs11" available';
?>
--EXPECT--
Extension "pkcs11" available
