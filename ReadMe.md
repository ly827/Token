###TokenClass使用说明

-------------

####GetToken
```php
use Common\Token;

$expire = 60*60;
$token = (new Token($expire))->getToken($params);

//return array
//[
//	'token'=>'token string', 
//	'ref'=>'ref string'
//]
```


####CheckToken
```php
use Common\Token;

$expire = 60*60;
$flag = (new Token($expire)->verification($token));

//return array
//[
//	'code'=>200,
//	'data'=>[
//		'params'=>'params data', 
//		'timer'=>'create time'
//	]
//]
//OR
//[
//	'code'=>400,
//	'msg'=>'msg string'
//]
```

####GetNewToken
```php
use Common\Token;

$expire = 60*60;
$token = (new Token($expire)->newToken($oldToken, $ref));

//return array
//[
//	'token'=>'token string', 
//	'ref'=>'ref string'
//]
//OR
//[
//	'code'=>401,
//	'msg'=>'msg string'
//]
```

------
####GetSign
```php
use Common\Token;
$sign = (new Token()->getSign($data));

//return string
```

####CheckSign
```php
use Common\Token;
$sign = (new Token()->signVerify($sign, $data));

//return true|false
```





