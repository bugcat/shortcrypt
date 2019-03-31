<?php namespace Bugcat\ShortCrypt\Cryption;

class BaseCrypt
{
    
    public function __construct()
    {
        
    }
    
    /**
     * 扩展的进制转换 支持2-62
     *     基于 base_convert ( string $number , int $frombase , int $tobase ) : string
     *
     * @param  string  $number     待转的值
     * @param  int     $frombase   原来的进制 2-62
     * @param  int     $tobase     目标的进制 2-62
     * @param  string  $priority   转化优先级 默认 lower_order
     *       upper_order:优先大写后顺序 10-35大写 36-61小写 10A 11B …… 35Z 36a 37b …… 61z
     *       lower_order:优先小写后顺序 10-35小写 36-61大写 10a 11b …… 35z 36A 37B …… 61Z
     *       order_upper:优先顺序但以大写为主 10A 11a 12B 13b 14C 15c …… 58Y 59y 60Z 61z
     *       order_lower:优先顺序但以小写为主 10a 11A 12b 13B 14c 15C …… 58y 59Y 60z 61Z
     * @return string  $new_bumber 
     */
    final static public function ext_convert(string $number, int $frombase, int $tobase, string $priority = 'lower_order')
    {
        $base_arr = ['upper_order', 'lower_order'];
        if ( $frombase <=36 && $tobase <= 36 && in_array($priority, $base_arr) ) {
            //若进制在36及以内 同时也是优先大小写 则使用 base_convert 
            $new_bumber = base_convert($number, $frombase, $tobase);
            return 'upper_order' == $priority ? strtoupper($new_bumber) : strtolower($new_bumber);
        }
        //TODO
    }
    
    /**
     * 异常处理
     *
     * @param  string  $err     错误信息
     * @return Exception 
     */
    static protected function exception(string $err)
    {
        throw new \Exception($err);
    }
    
    
    /**
     * 删除并返回字符串的一部分 Delete and return part of a string.
     *      基于 substr ( string $string , int $start [, int $length ] ) : string
     *
     * @param  string  $string  原字符串
     * @param  int     $start   必需。规定在字符串的何处开始。
     *                           正数 - 在字符串的指定位置开始
     *                           负数 - 在从字符串结尾开始的指定位置开始
     *                           0 - 在字符串中的第一个字符处开始
     * @param  int     $length  可选。规定被返回字符串的长度。默认是直到字符串的结尾。
     *                           正数 - 从 start 参数所在的位置返回的长度
     *                           负数 - 从字符串末端返回的长度
     * @param  int     $mode    可选。规定原字符串保留的部分。默认是0。
     *                           0  - 左右皆保留 
     *                           1  - 只保留右侧部分
     *                           -1 - 只保留左侧部分
     * @return string   
     */
    static public function strsub(string & $string , int ...$ints)
    {
        $start = $ints[0];
        if ( isset($ints[1]) ) {
            $length = $ints[1];
            $str = substr($string, $start, $length);
            $right = substr($string, $start + $length);
        } else {
            $str = substr($string, $start);
            $right = '';
        }
        $mode = $ints[2] ?? 0;
        $left = substr($string, 0, $start);
        if ( $mode > 0 ) {
            $string = $right;
        } elseif ( $mode < 0 ) {
            $string = $left;
        } else {
            $string = $left . $right;
        }
        return $str;
    }
}

