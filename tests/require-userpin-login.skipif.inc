<?php

if (!extension_loaded('pkcs11')) {
    echo 'skip - extension not loaded';
}

if (getenv('PHP11_MODULE') === false) {
    echo 'skip - module not specified';
}

if (getenv('PHP11_SLOT') === false) {
    echo 'skip - slot id not specified';
}

try {
	$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
    $session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
} catch (\Throwable $e) {
    echo 'skip - unable to open session';
}

if (getenv('PHP11_PIN') === false) {
    echo 'skip - PIN not specified';
}

try {
	$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));
	$session->logout();
} catch (\Throwable $e) {
    echo 'skip - unable to login as so';
}
