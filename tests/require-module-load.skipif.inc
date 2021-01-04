<?php

if (!extension_loaded('pkcs11')) {
    echo 'skip - extension not loaded';
}

if (getenv('PHP11_MODULE') === false) {
    echo 'skip - module not specified';
}

try {
    $module = new Pkcs11\Module(getenv('PHP11_MODULE'));
} catch (\Throwable $e) {
    echo 'skip - unable to load module';
}
