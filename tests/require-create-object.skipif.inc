<?php

require_once 'require-open-session.skipif.inc';

try {
    $rv = $module->C_CreateObject($session, [], $o11);
    if ($rv === Pkcs11\CKR_FUNCTION_NOT_SUPPORTED)
        echo 'skip - C_CreateObject CKR_FUNCTION_NOT_SUPPORTED';
} catch (\Throwable $e) {
}
