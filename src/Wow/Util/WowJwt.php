<?php
/**
 * PHP Wow Jwt
 *
 * PHP version 5
 * JWT RFC: http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-19
 *
 * @category Wow
 * @package  Util
 * @author   Tzeng, Yi-Feng <yftzeng@gmail.com>
 * @license  http://www.opensource.org/licenses/mit-license.php MIT
 * @link     https://github.com/yftzeng/phpWowJwt
 */

namespace Wow\Util;

/**
 * PHP Wow Jwt
 *
 * @category Wow
 * @package  Util
 * @author   Tzeng, Yi-Feng <yftzeng@gmail.com>
 * @license  http://www.opensource.org/licenses/mit-license.php MIT
 * @link     https://github.com/yftzeng/phpWowJwt
 */
class WowJwt
{

    private static $_alg;
    private static $_encrypt_alg = 'AES-256-CTR';
    private static $_encrypt_key = '1234567812345678';
    private static $_encrypt_iv  = '1234567812345678';

    /**
     * @param string $alg algorithm
     *
     * @comment set encrypt algorithm
     *
     * @return null
     */
    public static function setEncryptAlg($alg)
    {
        self::$_encrypt_alg = $alg;
    }

    /**
     * @param string $key algorithm key
     *
     * @comment set key for encrypt algorithm
     *
     * @return null
     */
    public static function setEncryptKey($key)
    {
        self::$_encrypt_key = $key;
    }

    /**
     * @param string $iv algorithm iv
     *
     * @comment set iv for encrypt algorithm
     *
     * @return null
     */
    public static function setEncryptIv($iv)
    {
        self::$_encrypt_iv = $iv;
    }

    /**
     * @param string $data data
     *
     * @comment return safe base64 url encode
     *
     * @return string
     */
    private static function _base64UrlEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * @param string $data data
     *
     * @comment return safe base64 url decode
     *
     * @return string
     */
    private static function _base64UrlDecode($data)
    {
        return base64_decode(strtr($data, '-_', '+/'));
    }

    /**
     * @param string $alg algorithm
     *
     * @comment get algorithm for hash_hmac
     *
     * @return string
     */
    private static function _getAlg($alg)
    {
        if ($alg[0] !== 'n' && $alg[0] !== 'H') {
            throw new \DomainException(
                'Unkonwn algorithm, or RSA/ECDSA algorithm not implemented.'
            );
        }
        if ($alg[2] === '2') {
            return 'sha256';
        }
        if ($alg[2] === '3') {
            return 'sha384';
        }
        if ($alg[2] === '5') {
            return 'sha512';
        }
        throw new \DomainException(
            'Unkonwn algorithm, or RSA/ECDSA algorithm not implemented.'
        );
    }

    /**
     * @param string $header  jwt header
     * @param string $payload jwt payload
     * @param string $key     jwt key
     *
     * @comment jwt token generator
     *
     * @return string
     */
    private static function _token($header, $payload, $key)
    {
        if ('none' === json_decode($header)->alg) {
            return '';
        }
        return self::_base64UrlEncode(
            hash_hmac(self::_getAlg(self::$_alg), $payload, $key, true)
        );
    }

    /**
     * @param string $payload jwt payload
     * @param string $key     jwt key
     * @param string $algo    jwt algorithm
     * @param bool   $encrypt encrypt jwt payload or not
     *
     * @comment jwt encode function
     *
     * @return string
     */
    public static function encode($payload, $key = '', $algo = 'HS256', $encrypt = false)
    {
        $header = '{"typ":"JWT","alg":"'.$algo.'"}';
        self::$_alg = $algo;
        if ($encrypt) {
            $payload = openssl_encrypt(
                $payload, self::$_encrypt_alg,
                self::$_encrypt_key, false, self::$_encrypt_iv
            );
        }
        $data = self::_base64UrlEncode($header) . '.' . self::_base64UrlEncode($payload);
        return $data . '.' . self::_token($header, $data, $key);
    }

    /**
     * @param string $jwt     jwt
     * @param string $key     jwt key
     * @param string $verify  jwt verification or not
     * @param bool   $encrypt encrypt jwt payload or not
     *
     * @comment jwt decode function
     *
     * @return string
     */
    public static function decode($jwt, $key = '', $verify = false, $encrypt = false)
    {
        $jwt = explode('.', $jwt);
        if (count($jwt) !== 3) {
            throw new UnexpectedValueException("Wrong JWT format: $jwt");
        }

        list($header, $payload, $token) = $jwt;
        $header_decode = self::_base64UrlDecode($header);
        if (null === json_decode($header_decode)) {
            throw new \UnexpectedValueException(
                "Syntax error, malformed JSON: $header_decode"
            );
        }

        $payload_decode = self::_base64UrlDecode($payload);
        if ($encrypt) {
            $payload_decode = openssl_decrypt($payload_decode, self::$_encrypt_alg, self::$_encrypt_key, false, self::$_encrypt_iv);
        }
        if ($verify) {
            if ($token !== self::_token($header_decode, $header.'.'.$payload, $key)) {
                throw new \UnexpectedValueException(
                    'JWT Signature verification failed'
                );
            }

            if (null === json_decode($payload_decode)) {
                throw new \UnexpectedValueException(
                    "Syntax error, malformed JSON: $payload_decode"
                );
            }
        }
        return $payload_decode;
    }
}
