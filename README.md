# shortcrypt 短位加密

## Installation

The ShortCrypt Service Provider can be installed via [Composer](http://getcomposer.org) by requiring the `bugcat/shortcrypt` package and setting the `minimum-stability` to `dev` in your project's `composer.json`.

```json
{
    "require": {
        "bugcat/shortcrypt": "~0.0"
    },
    "minimum-stability": "dev"
}
```

or

Require this package with composer:
```
composer require bugcat/shortcrypt
```

Update your packages with ```composer update``` or install with ```composer install```.

In Windows, you'll need to include the GD2 DLL `php_gd2.dll` in php.ini. And you also need include `php_fileinfo.dll` and `php_mbstring.dll` to fit the requirements of `bugcat/shortcrypt`'s dependencies.

## Usage

莫名其妙的需求：将一些字符串(目前仅支持数字)加密成密文 需要尽量短 多变 可解密


## Example Usage
```php
use Bugcat\ShortCrypt\NumberCrypter;

$nums = [54321, 9999, 2019];
$encrypted = NumberCrypter::encrypt($nums, 16);
var_dump($encrypted);
//string(16) "ln0l7pru15wxm1k3"

$decrypted = NumberCrypter::decrypt($encrypted);
var_dump($decrypted);
//array(3) { [0]=> string(5) "54321" [1]=> string(4) "9999" [2]=> string(4) "2019" }
```


