# phpldap  PHP封装LDAP扩展

## 安装 

```
composer require hanguangchao/phpldap
```

## 示例

```php
$config  = [
  'host' => 'ldap://youdoman.com:389',
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
 ];
$ldap = LdapApi::getInstance($config);
$result = $ldap->search('uid=test');
```
