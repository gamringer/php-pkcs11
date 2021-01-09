<?php

require_once 'require-module-load.skipif.inc';

if (getenv('PHP11_SLOT') === false) {
    echo 'skip - slot id not specified';
}

try {
    $session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
} catch (\Throwable $e) {
    echo 'skip - unable to open session';
}
