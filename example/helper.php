<?php

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