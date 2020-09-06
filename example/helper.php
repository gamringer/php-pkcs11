<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

if (getenv('PHP11_MODULE') === false)
  $modulePath = '/usr/local/lib/softhsm/libsofthsm2.so';
else
  $modulePath = getenv('PHP11_MODULE');

if (getenv('PHP11_PINCODE') === false)
  $pinCode = '123456';
else
  $pinCode = getenv('PHP11_PINCODE');


function rawToRsaPem($modulus, $exponent){
	$der = hex2bin('30820122300d06092a864886f70d01010105000382010f003082010a0282010100')
		 . $modulus
		 . hex2bin('0203')
		 . $exponent
	;

	return "-----BEGIN PUBLIC KEY-----\n"
		 . chunk_split(base64_encode($der), 64, "\n")
		 . "-----END PUBLIC KEY-----\n"
	;
}

function base64url_encode($data)
{
    $b64 = base64_encode($data);
    $url = strtr($b64, '+/', '-_');

    return rtrim($url, '=');
}

function base64url_decode($data, $strict = false)
{
    $b64 = strtr($data, '-_', '+/');

    return base64_decode($b64, $strict);
}
