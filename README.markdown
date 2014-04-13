# phpWowJwt

Wow! JWT for PHP. Fast Javascript Web Token library for PHP.

## Requirement

PHP 5.3+

## Usage

### Standalone WowLog library

```
include __DIR__.'/src/Wow/Util/WowJwt.php';

use Wow\Util\WowJwt as JWT;

$payload = '{"iss":"ant"}';
$key     = '1234567890';
$algo    = 'HS256';

$verify  = true;
$encrypt = false;

$t = JWT::encode($payload, $key, $algo, $encrypt);
echo $t."\n";
$t = JWT::decode($t, $key, $verify, $encrypt);
echo $t."\n";
```

### Work with Composer

#### Edit `composer.json`

```
{
    "require": {
        "yftzeng/wow-jwt": "dev-master"
    }
}
```

#### Update composer

```
$ php composer.phar update
```

#### Sample code
```
include 'vendor/autoload.php';

use Wow\Util\WowJwt as JWT;

$payload = '{"iss":"ant"}';
$key     = '1234567890';
$algo    = 'HS256';

$verify  = true;
$encrypt = false;

$t = JWT::encode($payload, $key, $algo, $encrypt);
echo $t."\n";
$t = JWT::decode($t, $key, $verify, $encrypt);
echo $t."\n";
```

## License

the MIT License
