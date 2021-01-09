<?php

require_once 'require-open-session.skipif.inc';

if (getenv('PHP11_PIN') === false) {
    echo 'skip - PIN not specified';
}

try {
	$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));
	$session->logout();
} catch (\Throwable $e) {
    echo 'skip - unable to login as so';
}
