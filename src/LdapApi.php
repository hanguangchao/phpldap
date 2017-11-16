<?php

namespace phpldap;

/**
 * @author hanguangchao <hanguangchao@gmail.com>
 * @copyright phpldap
 */

/**
 * PHP封装LDAP扩展
 *
 * ```php
 * $config  = [
 *     'host' => 'ldap://youdoman.com:389',
        'basedn' => 'dc=youdoman,dc=com',
        'binddn' => 'cn=adminuser',
        'bindpw' => 'pwd',
        'login_attribute' => 'uid',
        'fullname_attribute' => 'cn',
        'objectclass_org' => ['organizationalUnit', 'top'],
        'objectclass_person' => ['inetOrgPerson', 'posixAccount', 'top'],
        'log_path' => '/tmp/ldap',
        'log_enable' => true,
        'log_debug' => false,
 * ];
 * $ldap = LdapApi::getInstance($config);
 * $result = $ldap->search('uid=test');
 * 
 * ```
 */
class LdapApi
{
    private static $ldap = null;
    private $ds = null;

    //ldap服务配置
    private $host;
    public $basedn;
    public $binddn;
    private $bindpw;
    public $login_attribute;
    public $fullname_attribute;
    public $filter;
    
    //日志
    //log开关
    private $log_enable = false;
    //是否页面显示
    private $log_debug = false;
    //日志文件保存路径
    private $log_path = '/tmp';
    
    public function __construct($config = [])
    {
        try {
            $this->configure($config);

            $ds = $this->ds = ldap_connect($this->host);
            ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);
            ldap_set_option($ds, LDAP_OPT_REFERRALS, 0);
            $this->ds = $ds;
            $this->bind($this->binddn, $this->bindpw);
            return $this->ds;
        } catch (\Exception $e) {
            $this->log($e->getMessage());
        }
    }

    /**
     * @param array $config
     * @return LdapApi|null
     */
    public static function getInstance($config = [])
    {
        $class_key = md5(json_encode($config));
        if (! isset(self::$ldap[$class_key])) {
            self::$ldap[$class_key] = new LdapApi($config);
        }
        return self::$ldap[$class_key];
    }


    public function bind($dn, $password)
    {
        try {
            if (! ldap_bind($this->ds, $dn, $password)) {
                throw new \Exception('ldap connection failed.');
            }
        } catch (\Exception $e) {
            $this->log($e->getMessage());
        }
    }

    /**
     * 得到dn
     */
    public function getDn($entry)
    {
        try {
            if ($entry) {
                $dn = ldap_get_dn($this->ds, $entry);
            } else {
                return false;
            }
            if ('Success' !== ($last_error = ldap_error($this->ds))) {
                throw new \Exception('Error in search query: ' . $last_error);
            }
        } catch (\Exception $e) {
            $this->log($e->getMessage());
        }
        return $dn;
    }

    /**
     * first_entry
     * @param  string $filter ldap_search filter
     * @return resource       entry资源 | false
     */
    public function firstEntry($filter) 
    {
        $res = ldap_search($this->ds, $this->basedn, $filter);
        $first = ldap_first_entry($this->ds, $res);
        if ($first) {
            return $first;
        } else {
            return false;
        }
    }

    /**
     * @param $filter 查询条件
     * @param array $attributes 设置查询属性
     * @return array|bool
     */
    public function search($filter, $dn = '', $attributes = [])
    {
        $entries = [];
        try {
            if ($dn == '') {
                $dn = $this->basedn;
            }
            $result = ldap_search($this->ds, $dn, $filter, $attributes);
            $entries = ldap_get_entries($this->ds, $result);
            if ('Success' !== ($last_error = ldap_error($this->ds))) {
                throw new \Exception('Error in search query: ' . $last_error);
            } else {
                if ($entries['count'] == 0) {
                    return false;
                }
            }
        } catch (\Exception $e) {
            $this->log(__METHOD__ . ":" . $e->getMessage() . var_export(func_get_args(), true));
            return false;
        }
        return $entries;
    }

    /**
     * 加入新的条目到 LDAP 名录之中。
     * 语法: boolean ldap_add(int handle, string dn, array entry);
     * 参数 handle 为打开 LDAP 的代号。
     * 参数 dn 为要加入条目的具体 dn 字符串。
     * 参数 entry 为数组，为个体所有的条目，数组的内容是条目的相关信息
     */
    public function add($dn, $entry = [])
    {
        $lastIns = false;
        try {
            // 加入新条目
            $lastIns = ldap_add($this->ds, $dn, $entry);
            if (0 !== ($last_errno = ldap_errno($this->ds))) {
                throw new \Exception(sprintf("Error in add errno:%d\terror:%s\tline:%d\targs:%s", $last_errno, ldap_error($this->ds), __LINE__, var_export(func_get_args(), true) ));
            }
        } catch (\Exception $e) {
            $this->log($e->getMessage() . __METHOD__ . "\n" . var_export(func_get_args(), true));
            return false;
        }
        return $lastIns;
    }

    /**
     * @param array $entry
     * @return bool
     */
    public function modify($dn, $entry = [])
    {
        try {
            $result = ldap_modify($this->ds, $dn, $entry);

            if (0 !== ($last_errno = ldap_errno($this->ds))) {
                throw new \Exception(sprintf("Error in modify errno:%d\terror:%s\tline:%d\targs:%s", $last_errno, ldap_error($this->ds), __LINE__, var_export(func_get_args(), true) ));
            }
        } catch (\Exception $e) {
            $this->log($e->getMessage() . $dn . var_export($entry, true));
            return false;

        }
        return $result;
    }

    public function modifyCase($dn, $entry, $type)
    {
        switch ($type) {
            case 'add':
                $result = ldap_mod_add($this->ds, $dn, $entry);
                break;
            case 'del':
                $result = ldap_mod_del($this->ds, $dn, $entry);
                break;
            case 'replace':
                $result = ldap_mod_replace($this->ds, $dn, $entry);
                break;
            default:
                # code...
                break;
        }
        return $result;
    }

    /**
     * 删除dn
     * @param  string $dn dn
     * @return bool   成功 true | 失败false 
     */
    public function delete($dn)
    {
        try {
            $result = ldap_delete($this->ds, $dn);
            if (0 !== ($last_errno = ldap_errno($this->ds))) {
                throw new \Exception(sprintf("Error in modify errno:%d\terror:%s\tline:%d\targs:%s", $last_errno, ldap_error($this->ds), __LINE__, var_export(func_get_args(), true) ));
            }
        } catch(\Exception $e) {
            $this->log($e->getMessage());
            return false;
        }
        return $result;
    }

    /**
     * 生成LDAP中的加密算法 Ps : LDAP中SHA,SSHA,MD5加密方法是经过了特殊处理,所以需要PHP实现互操作
     * @param $password
     * @param $algo
     * @param $encrypt bool 是否已经是加密算法计算过的字符串
     * @return string
     * @throws \Exception
     */
    public static function password($password, $algo, $encrypt = false)
    {
        $method = "ldap_password_" . strtolower($algo);
        if (method_exists(__CLASS__, $method)) {
            return call_user_func(array(__CLASS__, $method), $password, $encrypt);
            // return $this->$method($password);
        }
        throw new \Exception('algo error.');
    }
    
    /**
     * SHA加密
     * @param $password  string 需要加密的字符串
     * @return string 返回加密号的字符串
     * */
    private static function ldap_password_sha($password)
    {
        $ldap_passwd = "{SHA}" . base64_encode(pack("H*", sha1($password)));
        return $ldap_passwd;
    }

    /**
     * SSHA加密算法
     * @param $password  string 需要加密的字符串
     * @return string 返回加密号的字符串
     * */
    private static function ldap_password_ssha($password)
    {
        $salt = "";
        for ($i=1; $i<=10; $i++) {
            $salt .= substr("0123456789abcdef", rand(0, 15), 1);
        }
        $hash = "{SSHA}" . base64_encode(pack("H*",sha1($password.$salt)).$salt);
        return $hash;
     }

    /**
     * MD5加密
     * @param $password
     * @param $encrypt bool false $password 为明文，  true $password为md5(明文)之后的字符串
     * @return string 返回加密号的字符串
     */
    public static function ldap_password_md5($password, $encrypt = false)
    {
        if (true === $encrypt) {
            $md5 = "{MD5}" . base64_encode(pack("H*", $password));
        } else {
            $md5 = "{MD5}" . base64_encode(pack("H*", md5($password)));
        }
        return $md5;
 }
    
    /**
     * @param $log
     */
    public function log($log)
    {
        if (false == $this->log_enable) {
            return;
        }
        $filename  = $this->log_path . '/ldap_' . date('Y-m-d') . '.log';
        $log = sprintf("%s\t%s\n", date('Y-m-d H:i:s'), $log);
        if (true == $this->log_debug) {
            echo $log;
        }
        error_log($log, 3, $filename);
    }

    /**
     * @param array $properties
     */
    public function configure($properties = [])
    {
        foreach ($properties as $name => $value) {
            $this->$name = $value;
        }
    }

    /**
     * 结束Ldap链接
     */
    public function __destruct()
    {
        return ldap_unbind($this->ds);
    }

    /**
     * 把dn转换成key-value数组形式
     * @param  string $dn dn
     * @return array  数组['ou' => [], 'dc' => []]
     */
    public function parseLdapDn($dn) 
    { 
        $parsr=ldap_explode_dn($dn, 0);
        $out = array();
        foreach($parsr as $key=>$value){ 
            if(false !== strstr($value, '=')){ 
                list($prefix,$data) = explode("=",$value); 
                //$data = preg_replace("/\\\\\\([0-9A-Fa-f]{2})/e", "''.chr(hexdec('\\\\1')).''", $data); 
                if(isset($current_prefix) && $prefix == $current_prefix){ 
                    $out[$prefix][] = $data;
                } else {
                    $current_prefix = $prefix; 
                    $out[$prefix][] = $data; 
                }
            }
        }

        return $out; 
    }

    /**
     * 获取rdn
     * @param  string $dn dn
     * @return string rdn || false 没得到
     */
    public function ldapRdn($dn)
    {
        $rdn = false;
        $parsr = ldap_explode_dn($dn, 0);
        foreach($parsr as $key=>$value) {
            if (false !== strstr($value, '=')) { 
                list($prefix,$data) = explode("=",$value); 
                if (strtoupper($prefix) == 'OU') {
                    $rdn = $data;
                    break;
                }
            }
        }
        return $rdn;
    }
}
