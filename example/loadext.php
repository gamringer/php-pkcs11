<?php

declare(strict_types=1);

$module = new Pkcs11\Module('/usr/lib/softhsm/libsofthsm2.so');

$info = $module->getInfo();
var_dump($info);

$slots = $module->getSlots();
var_dump($slots);

$module->initToken(5, 'PHP slot', '123456');

$slots = $module->getSlots();
var_dump($slots);
