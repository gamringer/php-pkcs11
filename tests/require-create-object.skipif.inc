<?php

require_once 'require-open-session.skipif.inc';

$o11 = new Pkcs11\P11Object();

try {
    $rv = $module->C_CreateObject($session, array(), $o11);
    if ($rv === Pkcs11\CKR_FUNCTION_NOT_SUPPORTED)
        echo 'skip - C_CreateObject CKR_FUNCTION_NOT_SUPPORTED';
} catch (\Throwable $e) {
}
