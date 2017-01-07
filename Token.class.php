<?php
namespace Common;
/**
 * 用户token生成校验
 * @authors Zhang Daomin (Beyondcommunistparty@gmail.com)
 * @date    2016-09-14 11:04:14
 * @version $Id$
 */

class Token
{
    /**
     * Token expire time
     * @var integer
     */
    public $expire = 60*60*24*7;

    public function __construct($expire=null)
    {
        if ($expire) {
            $this->expire = $expire;
        }
    }

    /**
     * Get Token
     * @Author   ZhangDaomin
     * @DateTime 2017-01-07T18:30:45+0800
     * @param    int|string|array     $params
     * @return   array                ['token','ref']
     */
    public function getToken($params = null)
    {
        if (!$params) {
            return null;
        }
        $time = time();
        return array(
                'token' => $this->encryption($params, $time),
                'ref' => $this->getRef($time)
            );
    }

    /**
     * verifica Token
     * @Author   ZhangDaomin
     * @DateTime 2017-01-07T18:33:24+0800
     * @param    string                   $token
     * @return   array
     */
    public function verification($token = '')
    {
        $data = $this->decryption($token);
        if (!$data) {
            return array(
                    'code' => 404,
                    'mag' => 'This token is not effective'
                );
        }

        if (!$data['params']) {
            return array(
                    'code' => 404,
                    'mag' => 'This token is not effective'
                );
        }
        if (($data['timer']+$this->expire) < time()) {
            return array(
                    'code' => 400,
                    'mag' => 'Long time not login'
                );
        }
        return array(
                'code' => 200,
                'data' => $data
            );
    }

    /**
     * Get new Token
     * @Author   ZhangDaomin
     * @DateTime 2017-01-07T18:34:26+0800
     * @param    string                   $token The old Token
     * @param    string                   $ref
     * @return   array                    ['Token', 'ref']
     */
    public function newToken($token='', $ref='')
    {
        $data = $this->decryption($token);
        if ($this->getRef($data['timer']) !== $ref) {
            return array(
                'code' => 401,
                'msg' => 'This ref code is mismatched'
            );
        } else {
            $time = time();
            return array(
                    'token' => $this->encryption($data['params'], $time),
                    'ref' => $this->getRef($time)
                );
        }
    }

    /**
     * encryption toekn
     * @Author   ZhangDaomin
     * @DateTime 2017-01-07T18:36:06+0800
     * @param    int|string|array         $params
     * @param    int                      $time
     * @return   string                   token string
     */
    protected function encryption($params, $time)
    {
        $time_64 = base64_encode($time);
        $id_64 = base64_encode(serialize($params));
        $one = strrev(str_replace('=', '0x33', $id_64.'|'.$time_64));
        $one_len = strlen($one);
        $mid = ceil($one_len/3);
        $left = substr($one, 0, $mid);
        $right = substr($one, $mid);
        $two = strrev($right).$left;
        return strrev(str_replace('=', '0x33', base64_encode($two)));
    }

    /**
     * decryption Token
     * @Author   ZhangDaomin
     * @DateTime 2017-01-07T18:37:30+0800
     * @param    string               $token
     * @return   array|null
     */
    protected function decryption($token)
    {
        $one = base64_decode(str_replace('33x0', '=', strrev($token)));
        $one_len = strlen($one);
        $mid = $one_len-ceil($one_len/3);
        $right = strrev(substr($one, 0, $mid));
        $left = substr($one, $mid);
        $two = str_replace('0x33', '=', strrev($left.$right));
        $data = array_map('base64_decode', explode('|', $two));
        if ($data[0] && $data[1]) {
            $data['params'] = unserialize($data[0]);
            $data['timer'] = $data[1];
            return $data;
        }
        return null;
    }

    /**
     * getRef
     * @Author   ZhangDaomin
     * @DateTime 2017-01-07T18:38:19+0800
     * @param    string                   $value [description]
     * @return   [type]                          [description]
     */
    protected function getRef($value = '')
    {
        return md5($value);
    }

    /**
     * Sign encryption
     * @Author   ZhangDaomin
     * @DateTime 2017-01-07T18:38:37+0800
     * @param    array                   $data [description]
     * @return   string                        [description]
     */
    protected function sign($data)
    {
        ksort($data);
        $string = "";
        while (list($key, $val)=each($data)) {
            $string .= $val;
        }
        return md5($string);
    }

    /**
     * get Sign
     * @Author   ZhangDaomin
     * @DateTime 2017-01-07T18:39:15+0800
     * @param    array                   $data [description]
     * @return   string                         [description]
     */
    public function getSign($data=null)
    {
        if (!$data) {
            return null;
        }
        return $this->sign($data);
    }

    /**
     * signVerify
     * @Author   ZhangDaomin
     * @DateTime 2017-01-07T18:39:58+0800
     * @param    string                   $secret [description]
     * @param    array                    $data   [description]
     * @return   bool                     true|false
     */
    public function signVerify($secret='', $data=[])
    {
        //file_put_contents('looooooooog.log', '------'.$secret, FILE_APPEND);
        $array = array();
        $array['secret'] = $secret;
        reset($data);
        while (list($key, $val) = each($data)) {
            if ($key != 'sign') {
                $array[$key] = $val;
            }
        }
        //file_put_contents('looooooooog.log', '------'.http_build_query($array), FILE_APPEND);
        $sign = $this->sign($array);
        //file_put_contents('looooooooog.log', '------'.$sign, FILE_APPEND);
        if ($sign == $data['sign']) {
            return true;
        }
        return false;
    }
}
