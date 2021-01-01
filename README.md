# PKCS11 bindings for PHP

Tested with the following HSMs:
* SafeNET Luna SA 4
* SoftHSM 2.6

## Compile
```
phpize
./configure
make
```

## Running tests
To make tests, ensure that SoftHSM2 is installed, configured and initialized.

### From Source Code

* Install from [source](https://github.com/opendnssec/SoftHSMv2)
* Create a directory where HSM files will be stored `/home/user/.softhsm`
* Create a configuration file in your home directory `~/.config/softhsm2/softhsm2.conf`
* Initialize token `softhsm2-util --init-token --slot 0 --label "My token 1"`

Example configuration file
```
directories.tokendir = /home/user/.softhsm
objectstore.backend = file
log.level = INFO
slots.removable = false
slots.mechanisms = ALL
```

Running tests
```
export PHP11_MODULE=/usr/local/lib/softhsm/libsofthsm2.so
export PHP11_SLOT=575024709
export PHP11_PIN=123456
make test
```

### From Ubuntu packages

```
# use bash
sudo apt install libsofthsm2-dev libsofthsm2 softhsm2-common softhsm2 pkcs11-dump locate
sudo updatedb

export SOFTHSM2_CONF=/tmp/php-pkcs11-softhsm2.conf
mkdir -p /tmp/php-pkcs11-softhsm
cat <<EOFCONF >> $SOFTHSM2_CONF
directories.tokendir = /tmp/php-pkcs11-softhsm
objectstore.backend = file
log.level = INFO
slots.removable = false
slots.mechanisms = ALL
EOFCONF

softhsm2-util --init-token --slot 0 --label "My token 1" --pin 123456 --so-pin 123456

export PHP11_MODULE=$(locate libsofthsm2.so | head -1)
export PHP11_SLOT=$(pkcs11-dump slotlist $PHP11_MODULE 2>/dev/null | grep SoftHSM | head -1)
export PHP11_PIN=123456

make test
```

## How to use

_All examples assume the use of a locally compiled installation of SoftHSM, but it will work with other modules as well._

### Loading a module
To load a PKCS11 module, create a new PKCS11\Module object.

```php
$modulePath = '/usr/local/lib/softhsm/libsofthsm2.so';
$module = new Pkcs11\Module($modulePath);
```

From the PKCS11\Module object, you can call most PKCS11 methods.

To get information the module:

```php
$moduleInfo = $module->getInfo();
```

### Slot Information
There are 2 methods to retrieve slots information. `getSlotList` can be used to retrieve a simple list of slots like `C_GetSlotList` would, while `getSlots` returns de result of `C_GetSlotInfo` for each available slot.

```php
$slotList = $module->getSlotList();
$slots = $module->getSlots();

$slotId = $slotList[0];

$slotInfo = $module->getSlotInfo($slotId);
```

### Token Information

```php
$tokenInfo = $module->getTokenInfo($slotId);
```

### Mechanisms
All mechanisms declared in PKCS11 version 3 are available under the Pkcs11 namespace.

```php
$mechanismList = $module->getMechanismList($slotId);
$mechanismInfo = $module->getMechanismInfo($slotId, Pkcs11\CKM_AES_GCM);
```

### Initializing a token
This extension supports initializing simple tokens via the `C_InitToken` function.

```php
$module->initToken($slotId, $label, $soPin);
```

### Opening a session
You can open a session and login as either a Security Officer or user. From the returned `Pkcs11\Session` object, more methods are available.

```php
$session = $module->openSession($slotId, Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_SO, $soPin);
$sessionInfo = $session->getInfo();
```

```php
$session = $module->openSession($slotId, Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, $userPin);
$sessionInfo = $session->getInfo();
```

### PIN Management
As a Security Officer, the user PIN can be set to any value.
```php
$session->login(Pkcs11\CKU_SO, $soPin);
$session->initPin($userPin);
$session->logout();
```

As either user, the current user PIN can be changed.
```php
$session->login(Pkcs11\CKU_SO, $soPin);
$session->setPin($soPin, $newPin);
$session->logout();
```
```php
$session->login(Pkcs11\CKU_USER, $userPin);
$session->setPin($userPin, $newPin);
$session->logout();
```

### Generating Keys
You can generate symmetric keys for any available mechanism.

```php
$key = $session->generateKey(new Pkcs11\Mechanism(Pkcs11\CKM_AES_KEY_GEN), [
  Pkcs11\CKA_CLASS => Pkcs11\CKO_SECRET_KEY,
  Pkcs11\CKA_SENSITIVE => true,
  Pkcs11\CKA_ENCRYPT => true,
  Pkcs11\CKA_DECRYPT => true,
  Pkcs11\CKA_VALUE_LEN => 32,
  Pkcs11\CKA_KEY_TYPE => Pkcs11\CKK_AES,
  Pkcs11\CKA_LABEL => "Test AES",
  Pkcs11\CKA_PRIVATE => true,
]);
```
```php
$keypair = $session->generateKeyPair(new Pkcs11\Mechanism(Pkcs11\CKM_EC_KEY_PAIR_GEN), [
  Pkcs11\CKA_VERIFY => true,
  Pkcs11\CKA_LABEL => "Test ECDSA Public",
  Pkcs11\CKA_EC_PARAMS => hex2bin('06082A8648CE3D030107'),
],[
  Pkcs11\CKA_TOKEN => false,
  Pkcs11\CKA_PRIVATE => true,
  Pkcs11\CKA_SENSITIVE => true,
  Pkcs11\CKA_SIGN => true,
  Pkcs11\CKA_LABEL => "Test ECDSA Private",
]);

$pkey = $keypair->pkey;
$skey = $keypair->skey;
```

### Encrypt/Decrypt
Given a symmetric key, you can encrypt something. Certain encryption mechanisms require a special Parameters object. Currently, the following are available:

* Pkcs11\GcmParams
* Pkcs11\Salsa20Params
* Pkcs11\ChaCha20Params
* Pkcs11\Salsa20Chacha20Poly1305Params

```php
$iv = random_bytes(16);
$aad = '';
$tagLength = 128;
$gcmParams = new Pkcs11\GcmParams($iv, $aad, $tagLength);

$data = 'Hello World!';
$mechanism = new Pkcs11\Mechanism(Pkcs11\CKM_AES_GCM, $gcmParams);
$ciphertext = $key->encrypt($mechanism, $data);
var_dump(bin2hex($ciphertext));
// string(56) "67940e19213d68c88d163b12d6cd565300f70d693309b5b744085b35"

$plaintext = $key->decrypt($mechanism, $ciphertext);
var_dump($plaintext);
// string(12) "Hello World!"
```

Given an RSA public key, you can encrypt a symmetric key. Similarly to symmetric mechanisms, some asymmetric encryption mechanisms require a special Parameters object. Currently, the following are available:

* Pkcs11\RsaOaepParams

```php
$keypair = $session->generateKeyPair(new Pkcs11\Mechanism(Pkcs11\CKM_RSA_PKCS_KEY_PAIR_GEN), [
  Pkcs11\CKA_ENCRYPT => true,
  Pkcs11\CKA_MODULUS_BITS => 2048,
  Pkcs11\CKA_PUBLIC_EXPONENT => hex2bin('010001'),
  Pkcs11\CKA_LABEL => "Test RSA Encrypt Public",
],[
  Pkcs11\CKA_TOKEN => false,
  Pkcs11\CKA_PRIVATE => true,
  Pkcs11\CKA_SENSITIVE => true,
  Pkcs11\CKA_DECRYPT => true,
  Pkcs11\CKA_LABEL => "Test RSA Encrypt Private",
]);

// SoftHSM2 only supports CKG_MGF1_SHA1
$oaepParam = new Pkcs11\RsaOaepParams(Pkcs11\CKM_SHA_1, Pkcs11\CKG_MGF1_SHA1);
$mechanism = new Pkcs11\Mechanism(Pkcs11\CKM_RSA_PKCS_OAEP, $oaepParam);

$symkey = random_bytes(32);
$ciphertext = $keypair->pkey->encrypt($mechanism, $symkey);
var_dump($ciphertext);

$plaintext = $keypair->skey->decrypt($mechanism, $ciphertext);
var_dump($plaintext);
```

### Derivation
Given an EC public key, you can derive a shared secret.

```php
// P-384
$domainParameters = hex2bin('06052B81040022');
$rawPublickeyOther = hex2bin('049f0a09e8a6fc87f4804642c782b2cd3e566b3e62262090d94e12933a00916f559b62ea33197706a302f0722b781a9349ea8f0f2bcea854cdcf5d9ff0e0a19c3c35d63578292307d1d83031c0134700c2990ed5b38f6c92245103c2c1352132a3');

$keypair = $session->generateKeyPair(new Pkcs11\Mechanism(Pkcs11\CKM_EC_KEY_PAIR_GEN), [
  Pkcs11\CKA_LABEL => "Test ECDH Public",
  Pkcs11\CKA_EC_PARAMS => $domainParameters,
],[
  Pkcs11\CKA_PRIVATE => true,
  Pkcs11\CKA_SENSITIVE => true,
  Pkcs11\CKA_DERIVE => true,
  Pkcs11\CKA_LABEL => "Test ECDH Private",
]);

$shared = '';

// SoftHSM2 only supports CKD_NULL
$params = new Pkcs11\Ecdh1DeriveParams(Pkcs11\CKD_NULL, $shared, $rawPublickeyOther);
$mechanism = new Pkcs11\Mechanism(Pkcs11\CKM_ECDH1_DERIVE, $params);
$secret = $keypair->skey->derive($mechanism, [
  Pkcs11\CKA_CLASS => Pkcs11\CKO_SECRET_KEY,
  Pkcs11\CKA_KEY_TYPE => Pkcs11\CKK_AES,
  Pkcs11\CKA_SENSITIVE => false,
  Pkcs11\CKA_EXTRACTABLE => true,
  Pkcs11\CKA_ENCRYPT => true,
  Pkcs11\CKA_DECRYPT => true,
]);

$rawSecret = $secret->getAttributeValue([Pkcs11\CKA_VALUE])[Pkcs11\CKA_VALUE];
```
