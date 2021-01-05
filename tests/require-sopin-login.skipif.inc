<?php

require_once 'require-open-session.skipif.inc';

if (getenv('PHP11_SOPIN') === false) {
    echo 'skip - SOPIN not specified';
}

try {
	$session->login(Pkcs11\CKU_SO, getenv('PHP11_SOPIN'));
	$session->logout();
} catch (\Throwable $e) {
    echo 'skip - unable to login as so';
}
