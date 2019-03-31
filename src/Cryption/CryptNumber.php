<?php namespace Bugcat\ShortCrypt\Cryption;

use Bugcat\ShortCrypt\Cryption\BaseCrypt;

class CryptNumber extends BaseCrypt
{
    
    const TYPE = [
        //量很小数大 三个数字 最大不超过 string(16) "3656158440062975" 标记
        //'less' => ['max_cnt' => 3, 'max_val' => 3656158440062975, 'tag_len' => 0], 
        
        //量多数小 十个数字 最大不超过 string(5) "46655" 标记
        //'lot' => ['max_cnt' => 10, 'max_val' => 46655, 'tag_len' => 0],  
        
        //量一般数一般 五个数字 最大不超过 string(11) "78364164095" 一位信息 + 标记
        'small' => ['max_cnt' => 5, 'max_val' => 78364164095, 'tag_len' => 1], 
        
        //量多数一般 十个数字  最大不超过 string(11) "78364164095" 两位信息 + 标记
        'medium' => ['max_cnt' => 10, 'max_val' => 78364164095, 'tag_len' => 2], 
        
        //量很多数很大 十五个数字 最大不超过 string(16) "3656158440062975" 三位信息 + 标记
        // TODO 这个好像有问题 后续改进
        //'big' => ['max_cnt' => 15, 'max_val' => 3656158440062975, 'tag_len' => 3], 
    ];
    
    //前缀干扰字符数
    const PRE_CHAR_NUM = 1;
    
    //加密层次 每增加一级 每个数字就会多记录一位
    const CRYPT_LEVEL = 0;
    
    
    /**
     * 加密数字组
     *
     * @param  string $type 加密类型
     * @param  array  $nums 数字组 
     * @param  int    $long 加密长度 默认16 0表示自由长度
     * @param  bool   $sensitive 结果是否区分大小写 默认false不区分全小写
     * @return string $cryptstr 加密结果
     */
    final static protected function enNumber($type, $nums, $long = 16, $sensitive = false)
    {
        $info = self::checknums($type, $nums);
        
        //加密结果的字符串
        $cryptstr = ''; 
        
        //第一步 添加前缀干扰字符
        self::setJamChar($cryptstr, self::PRE_CHAR_NUM, $sensitive);
        
        //第二步 记录数字组的数量 
        $tag_num = '';
        $num_long = count($nums);
        $max_rand = floor(36 / $info['max_cnt']);
        $rand = mt_rand(0, $max_rand - 1);
        $tag_num = $rand * $info['max_cnt'] + $num_long;
        $tag_num = self::ext_convert($tag_num, 10, 36, 'lower_order');
        
        //第三步 将数组加密进去
        $tags = ''; //记录每个数字标记的信息
        $num_str = ''; //记录数字组的字符串
        $str_len = self::PRE_CHAR_NUM + 1 + $info['tag_len']; //计算出加密结果的最小长度
        $keys = array_keys($nums);
        shuffle($keys); //将数字组的键顺序打乱
        //按新顺序遍历数字组
        foreach ( $keys as $k ) {
            //加密这一个数字
            $number = $nums[$k]; //这个数字
            $len = self::encryptOne($type, $number, $k, $num_str, $tags);
            $str_len += $len;
            if ( $long > 0 && $str_len > $long ) {
                self::exception('The $long value is too small.');
            }
        }
        //将标记信息的字符串转成36进制
        if ( in_array($type, ['small', 'medium']) ) {
            $tags = self::ext_convert($tags, 2, 36, 'lower_order');
        }
        
        //第四步 组装字符串
        $cryptstr .= $tag_num . $tags . $num_str;
        
        //每五步 在末尾添加干扰字符
        if ( $long > 0 ) {
            self::setJamChar($cryptstr, $long - $str_len, $sensitive);
        }
        
        return $cryptstr;
    }
    
    /**
     * 解密数字组
     *
     * @param  str  $type 加密类型
     * @param  str  $cryptstr 密文 
     * @return arr  $nums 加密结果
     */
    final static protected function deNumber($type, $cryptstr)
    {
        //第一步 去除前缀干扰字符 
        $prechar = self::strsub($cryptstr, 0, self::PRE_CHAR_NUM);
        
        //第二步 取出记录数字组的数量
        $tag_num = self::strsub($cryptstr, 0, 1);
        $tag_num = self::ext_convert($tag_num, 36, 10, 'lower_order');
        $tag_num = $tag_num % self::TYPE[$type]['max_cnt'];
        
        //第三步 取出数字标记的信息
        $tags = substr($str, 0, self::TYPE[$type]['tag_len']);
        
        //第四步 开始分解加密字符串
        
        return $tags;
        
        $arr = self::decryptArr($type, $str);
        
        
        return $arr;
    }
    
    
    /**
     * 检测传入参数是否合法
     *
     * @param  string $type 
     * @param  array  $nums 数字组 
     * @return array    
     */
    final static private function checknums($type, $nums)
    {
        if ( !isset(self::TYPE[$type]) ) {
            self::exception('The $type value is invalid.');
        }
        $info = self::TYPE[$type];
        //先判断数组数量是否超过
        if ( empty($nums) || $info['max_cnt'] < count($nums) ) {
            self::exception('The number of elements of the parameter $nums must be between 1 and '.$info['max_cnt']);
        }
        sort($nums, SORT_NUMERIC);
        //再判断数组中的数字是否达到要求
        if ( min($nums) < 0 || max($nums) > $info['max_val'] ) {
            self::exception('The element of the parameter $nums must be between 0 and '.$info['max_val']);
        }
        return $info;
    }
    
    /**
     * 添加干扰字符
     *
     * @param  string $string 
     * @param  int    $length 字符数量
     * @param  bool   $sensitive
     * @return string    
     */
    final static private function setJamChar(& $string, $length, $sensitive)
    {
        $pool = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        $str = '';
        for ( $i = 0; $i < $length; $i++ ) {
            $str .= substr(str_shuffle($pool), 0, 1);
        }
        $string .= $sensitive ? $str : strtolower($str);
        return true;
    }
    
    /**
     * 加密其中一个数字
     *
     * @param  str $type    加密方式
     * @param  int $number  这个数字
     * @param  int $k       这个数字原键
     * @param  str $num_str 加密后的数字字符串
     * @param  str $tags    记录标记的字符
     * @return int 这一个数字加密后的长度
     */
    final static private function encryptOne($type, $number, $k, & $num_str, & $tags)
    {
        //先将这个数字转成36进制
        //TODO 最好让每一位数字的加密方式不同 这样在有相同数字时结果也不同
        //待优化更优算法
        $num_36 = self::ext_convert($number, 10, 36, 'lower_order');
        $num_len = strlen($num_36);
        //根据不同类型 得到不同的特征码 特征码是两位十进制数
        if ( in_array($type, ['lot', 'small', 'medium']) ) {
            //十位是36进制的长度减一 个位是数字原来的键
            $sign = ($num_len - 1) * 10 + $k;
        } else {
            //十位是数字原来的键 个位是36进制的长度减一
            $sign = $k * 10 + (strlen($num_36) - 1);
        }
        switch ( $type ) {
            case 'lot':
            case 'less':
                //标记不会超过29 故无需记录标记信息
                break;  
            case 'small':
            case 'medium':
                //标记不会超过69 故需记录二进制标记信息
                if ( $sign >= 36 ) {
                    //$sign最大值为69所以不用考虑72+的情况
                    $tags .= '1';
                    $sign -= 36;
                } else {
                    $tags .= '0';
                }
                break;
            default:
                self::exception('The $type value is invalid.');
        }
        $sign = self::ext_convert($sign, 10, 36, 'lower_order');
        $num_str .= $sign . $num_36;
        return $num_len + 1;
    }
    
    /**
     * 将加密的数字组一一解析出来
     *
     * @param  str $type    加密方式
     * @param  str $cryptstr 加密后的数字字符串
     * @return arr 返回解密后的数字组
     */
    final static private function decryptArr($type, $cryptstr)
    {
        $tags = substr($cryptstr, 0, self::TYPE[$type]['tag_len']);
        return $tags;
        
        if ( in_array($type, ['small', 'medium']) ) {
            //$tags = self::ext_convert($tags, 2, 36, 'lower_order');
        }
        //先将这个数字转成36进制
        //TODO 最好让每一位数字的加密方式不同 这样在有相同数字时结果也不同
        //待优化更优算法
        $num_36 = self::ext_convert($number, 10, 36, 'lower_order');
        $num_len = strlen($num_36);
        //根据不同类型 得到不同的特征码 特征码是两位十进制数
        if ( in_array($type, ['lot', 'small', 'medium']) ) {
            //十位是36进制的长度减一 个位是数字原来的键
            $sign = ($num_len - 1) * 10 + $k;
        } else {
            //十位是数字原来的键 个位是36进制的长度减一
            $sign = $k * 10 + (strlen($num_36) - 1);
        }
        switch ( $type ) {
            case 'lot':
            case 'less':
                //标记不会超过29 故无需记录标记信息
                break;  
            case 'small':
            case 'medium':
                //标记不会超过69 故需记录二进制标记信息
                if ( $sign >= 36 ) {
                    //$sign最大值为69所以不用考虑72+的情况
                    $tags .= '1';
                    $sign -= 36;
                } else {
                    $tags .= '0';
                }
                break;
            default:
                self::exception('The $type value is invalid.');
        }
        $sign = self::ext_convert($sign, 10, 36, 'lower_order');
        $num_str .= $sign . $num_36;
        return $num_len + 1;
    }
    
}
