<?php namespace Bugcat\ShortCrypt;

use Bugcat\ShortCrypt\Cryption\CryptNumber;

class NumberCrypter extends CryptNumber
{
    
    public static function __callStatic($name, $arguments)
    {
        //如果是加密请求
        $_name = 'encrypt' == $name ? 'encryptSmall' : $name;
        $type = strtolower( ltrim($_name, 'encrypt') );
        if ( !empty($type) && isset(self::TYPE[$type]) ) {
            /**
             * 加密数字组
             *
             * @param  string $type 加密类型
             * @param  array  $nums 数字组 对数字个数及值大小有要求 详见 CryptNumber::TYPE
             * @param  int    $long 加密长度 默认16
             * @param  bool   $sensitive 结果是否区分大小写 默认false不区分全小写
             * @return string 加密结果
             */
            $nums = $arguments[0] ?? [];
            $long = $arguments[1] ?? 16;
            $sensitive = $arguments[2] ?? false;
            return self::enNumber($type, $nums, $long, $sensitive);
        }
        
        //如果是解密请求 TODO
        $_name = 'decrypt' == $name ? 'decryptSmall' : $name;
        $type = strtolower( ltrim($_name, 'decrypt') );
        if ( !empty($type) && isset(self::TYPE[$type]) ) {
            /**
             * 解密数字组
             *
             * @param  str  $type 加密类型
             * @param  str  $cryptstr 密文 
             * @return arr  $nums 加密结果
             */
            $cryptstr = $arguments[0] ?? '';
            return self::deNumber($type, $cryptstr);
        }
        
        self::exception('The call name is invalid.');
    }
    
}
