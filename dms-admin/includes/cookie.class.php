<?php

# Cache Cookie - (C) 2011 Frank Denis - Public domain
# Modified BCA

class CacheCookie {
    static var $config;
    
    static function init($config)
    {
      self::$config = $config;
    }
    
    static function set($key, $value, $lifetime) {
        global $__wicked;
        $config = $__wicked['modules']['cookie_session'];
        
        $cookie_content = self::_fetch_cookie_content();
        $now = time();
        $cookie_content->{$key} = array('value' => $value,
                                        'expires_at' => $now + $lifetime);
        $cookie_json = json_encode($cookie_content);
        $cookie = hash_hmac(self::$config['digest_method'], $cookie_json,
                            self::$config['secret_key']) . '|' . $cookie_json;
        self::_wipe_previous_cookie(self::$config['name']);
        setcookie(self::$config['name'], $cookie, $now + self::$config['ttl'],
                  self::$config['path'], self::$config['domain'], FALSE, TRUE);
        $_COOKIE[self::$config['name']] = $cookie;

        return TRUE;
    }
    
    static function get($key) {
        $cookie_content = self::_fetch_cookie_content();
        if (!isset($cookie_content->{$key})) {
            return NULL;
        }
        $entry = $cookie_content->{$key};
        if (!is_object($entry) || !isset($entry->value) ||
            !isset($entry->expires_at) ||
            !is_numeric($entry->expires_at) || time() > $entry->expires_at) {
            self::delete($key);
            
            return NULL;
        }
        return $entry->value;
    }
    
    static function delete($key) {
        global $__wicked;
        $config = $__wicked['modules']['cookie_session'];

        $cookie_content = self::_fetch_cookie_content();
        $key_existed = isset($cookie_content->{$key});
        unset($cookie_content->{$key});
        $cookie_json = json_encode($cookie_content);
        $cookie = hash_hmac(self::$config['digest_method'], $cookie_json,
                            self::$config['secret_key']) . '|' . $cookie_json;
        self::_wipe_previous_cookie(self::$config['name']);
        setcookie(self::$config['name'], $cookie, time() + self::$config['ttl'],
                  self::$config['path'], self::$config['domain'], FALSE, TRUE);
        $_COOKIE[self::$config['name']] = $cookie;        
        
        return $key_existed;
    }
    
    static function delete_all() {
        global $__wicked;
        $config = $__wicked['modules']['cookie_session'];

        self::_wipe_previous_cookie(self::$config['name']);
        setcookie(self::$config['name'], '', 1, self::$config['path'], self::$config['domain'],
                  FALSE, TRUE);
        unset($_COOKIE[self::$config['name']]);
    }
    
    protected static function _wipe_previous_cookie($cookie_name) {
        $headers = headers_list();
        header_remove();
        $rx = '/^Set-Cookie\\s*:\\s*' . preg_quote($cookie_name) . '=/';
        foreach ($headers as $header) {
            if (preg_match($rx, $header) <= 0) {
                header($header, TRUE);
            }
        }
    }
    
    protected static function _fetch_cookie_content() {
        $cookie = NULL;
        if (!empty($_COOKIE[self::$config['name']])) {
            $cookie = $_COOKIE[self::$config['name']];
        }
        if (empty($cookie)) {
            $cookie_content = new \stdClass();
        } else {
            @list($digest, $cookie_json) = explode('|', $cookie, 2);
            if (empty($digest) || empty($cookie_json) ||
                !self::hash_equals($digest, hash_hmac(self::$config['digest_method'], $cookie_json,
                                      self::$config['secret_key'])) {
                $cookie_content = new \stdClass();
            } else {
                $cookie_content = @json_decode($cookie_json);
            }
        }
        if (!is_object($cookie_content)) {
            $cookie_content = new \stdClass();
        }
        return $cookie_content;
    }
    

    /**
     * Prevent timing attack
     * 
     * @param  string $knownString
     * @param  string $userString
     * @return bool
     */
    public static function hash_equals($knownString, $userString)
    {
        if (function_exists('\hash_equals')) {
            return \hash_equals($knownString, $userString);
        }
        if (strlen($knownString) !== strlen($userString)) {
            return false;
        }
        $len = strlen($knownString);
        $result = 0;
        for ($i = 0; $i < $len; $i++) {
            $result |= (ord($knownString[$i]) ^ ord($userString[$i]));
        }
        // They are only identical strings if $result is exactly 0...
        return 0 === $result;
    }
}
