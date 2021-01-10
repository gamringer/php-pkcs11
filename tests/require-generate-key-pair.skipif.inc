<?php

require_once 'require-open-session.skipif.inc';

try {
    $rv = $module->C_GenerateKeyPair($session,
                      new Pkcs11\Mechanism(Pkcs11\CKM_RSA_PKCS_KEY_PAIR_GEN),
                      [], [], $pubKey, $privKey);
    if ($rv === Pkcs11\CKR_FUNCTION_NOT_SUPPORTED)
        echo 'skip - C_GenerateKeyPair CKR_FUNCTION_NOT_SUPPORTED';
} catch (\Throwable $e) {
}
