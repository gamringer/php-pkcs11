--TEST--
Failed Module constructor does not corrupt library registry
--SKIPIF--
<?php
require_once 'require-module-load.skipif.inc';
?>
--FILE--
<?php
declare(strict_types=1);

/* Attempt to load a non-existent library */
try {
    $bad = new Pkcs11\Module('/nonexistent/libfake.so');
} catch (\Throwable $e) {
    echo "caught: " . (strpos($e->getMessage(), 'Unable to initialise') !== false ? 'yes' : 'no') . "\n";
}

/* Now load the real library — must work */
$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$info = $module->getInfo();
var_dump(isset($info['libraryDescription']));

/* Clean up — must not crash */
unset($module);
echo "OK\n";
?>
--EXPECT--
caught: yes
bool(true)
OK
