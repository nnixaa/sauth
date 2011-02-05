<?php

/**
 * Authorisation with vkontakte
 */
class SAuth_Provider_Vkontakte {
    
    /**
     * @var array Configuration array
     */
    protected $_config = array(
        'apiId' => '',
        'apiSecret' => '',
        'redirectUrl' => '',
    );
    
    /**
     * @var string Session key
     */
    protected $_sessionKey = 'SAUTH_VKONTAKTE';
    
    /**
     * @var Zend_Session_Namespace Session storage
     */
    protected $_sessionStorage = null;
    
    /**
     * @var int Session live time
     */
    protected $_sessionLiveTime = 86400;
    
    /**
     * Object constructor method
     * @param array $config
     */
    public function __construct($config = array()) {
        
        $this->setConfig($config);
        $this->setUpSessionStorage();
    }
    
    /**
     * Returns authorization flag
     * @return bool
     */
    public function isAuthorized() {
        
        $tokenAccess = $this->_getTokenAccess();
        return empty($tokenAccess) ? false : true;
    }
    
    /**
     * Authorized user
     * @param array $config
     * @return true
     */
    public function auth(array $config = array()) {
        
        if ($this->isAuthorized()) {
            return true;
        }
        
        $config = $this->setConfig($config);
        
        $apiId = $config['apiId'];
        $apiSecret = $config['apiSecret'];
        
        if (empty($apiId) || empty($apiId)) {
            throw new SAuth_Exception('Vkontakte auth configuration not specifed.');
        }
        $appCookie = isset($_COOKIE['vk_app_' . $apiId]) ? $this->_parseResponse($_COOKIE['vk_app_' . $apiId]) : null;
        $vkUserCookie = isset($_COOKIE['vk_user_info_' . $apiId]) ? $this->_parseResponse($_COOKIE['vk_user_info_' . $apiId]) : null;
        if (!empty($appCookie)) {
            //create sign
            $sign = 'expire=' . $appCookie['expire'] . 'mid=' . $appCookie['mid'] . 'secret=' . $appCookie['secret']
                . 'sid=' . $appCookie['sid'];
            $sign =  md5($sign . $apiSecret);
            if ($appCookie['sig'] == $sign) {
                $this->_setTokenAccess($sign);
                $this->setUserParameters((array) $appCookie);
                $this->setUserParameters((array) $vkUserCookie);
                //unset vk info cookie
                setcookie('vk_user_info_' . $apiId, '', time()-1000, '/');
                
                if (!empty($config['redirectUrl'])) {
                    header('Location:' . $config['redirectUrl']);
                    exit(1);
                }
                return $this->isAuthorized();
            }
        }
        return false;
    }
    
    /**
     * Getting authentication identification
     * @return false|int User ID
     */
    public function getAuthId() {
        
        $id = (int) $this->getUserParameters('id');
        return $id > 0 ? $id : false;
    }
    
    /**
     * TODO: Cant select multi-level arrays
     * Returns user parameters
     * @param string $key
     * @return mixed
     */
    public function getUserParameters($key = null) {
        
        $sessionStorage = $this->getSessionStorage();
        $userParameters = (array) $sessionStorage->userParameters;
        
        if (!empty($userParameters)) {
            
            if ($key != null) {
                $key = (string) $key;
                return isset($userParameters[$key]) ? $userParameters[$key] : false;
            }
        }
        return $userParameters;
    }
    
    /**
     * Setting user parameters in session
     * @param array $userParameters
     * @return array
     */
    public function setUserParameters(array $userParameters) {
            
        $params = $this->getUserParameters();
        foreach ($userParameters as $key => $value) {
            $params[$key] = $value;
        }
        $sessionStorage = $this->getSessionStorage();
        return $sessionStorage->userParameters = $params;
    }
        
    /**
     * Clear saved access token
     */
    public function clearAuth() {
        $this->getSessionStorage()->unsetAll();
    }
    
    /**
     * Setting up session storage
     * @return Zend_Session_Namespace
     */
    public function setUpSessionStorage() {
        
        $sessionKey = (string) $this->getSessionKey();
        if (empty($sessionKey)) {
            throw new SAuth_Exception('Invalid facebook auth storage key');
        }
        $this->_sessionStorage = new Zend_Session_Namespace($sessionKey);
        $this->_sessionStorage->setExpirationSeconds($this->getSessionLiveTime());
        return $this->_sessionStorage;
    }
    
    /**
     * Getting session storage
     * @return Zend_Session_Namespace
     */
    public function getSessionStorage() {
        
        return $this->_sessionStorage;
    }
    
    /**
     * Setting configuration
     * @param array $config
     * @return array Configuration array
     */
    public function setConfig(array $config = array()) {
            
        foreach ($config as $key => $value) {
            switch ($key) {
                case 'sessionKey':
                    $this->setSessionKey($value);
                    unset($config[$key]);
                    break;
                case 'sessionLiveTime':
                    $this->setSessionLiveTime($value);
                    unset($config[$key]);
                default:
                    break;
            }
            $this->_config[$key] = $value;
        }
        return $this->getConfig();
    }
    
    /**
     * Getting configuration
     * @param string $key
     * @return array Configuration array
     */
    public function getConfig($key = null) {
            
        $key = (string) $key;
        if ($key != null && isset($this->_config[$key])) {
            return isset($this->_config[$key]) ? $this->_config[$key] : false;
        }
        return $this->_config;
    }
    
    /**
     * Setting session key
     * After setSession key you must reset session storage calling setUpSessionStorage
     * @param string $key 
     * @return false|string
     */
    public function setSessionKey($key) {
        
        $key = (string) $key;
        if (!empty($key)) {
            return $this->_sessionKey = $key;
        }
        return false;
    }
    
    /**
     * Getting session key
     * @return string
     */
    public function getSessionKey() {
        
        return $this->_sessionKey;
    }
    
    /**
     * Settion session live time
     * @param int $time
     * @return false|int
     */
    public function setSessionLiveTime($time) {
        if ($time > 0) {
            return $this->_sessionLiveTime = (int) $time;
        }
        return false;
    }

    /**
     * Gettion session live time
     * @return int
     */
    public function getSessionLiveTime() {

        return $this->_sessionLiveTime;
    }
    
    /**
     * Parse url
     * @param string $body
     * @return array
     */
    protected function _parseResponse($body) {
        if (is_string($body) && !empty($body)) {
            $body = trim($body);
            $pairs = explode('&', $body);
            $parsed = array();
            if (is_array($pairs)) {
                foreach ($pairs as $pair) {
                    if (!empty($pair)) {
                        list($key, $value) = explode('=', $pair, 2);
                        if (!empty($key) && !empty($value)) {
                            $parsed[$key] = $value;
                        }
                    }
                }
            }
            return $parsed;
        }
        return false;
    }

    /**
     * Trying get token access from session storage
     * @return false|string
     */
    protected function _getTokenAccess() {
        
        $sessionStorage = $this->getSessionStorage();
        return !empty($sessionStorage->tokenAccess) ? unserialize($sessionStorage->tokenAccess) : false;
    }

    /**
     * Seting token access from session storage
     * @param string $tokenAccess
     * @return string
     */
    protected function _setTokenAccess($tokenAccess) {
        
        $sessionStorage = $this->getSessionStorage();
        return $sessionStorage->tokenAccess = serialize($tokenAccess);
    }

    /**
     * Unset token access from session storage
     */
    protected function _unsetTokenAccess() {
            
        $sessionStorage->tokenAccess = null;
        unset($sessionStorage->tokenAccess);
    }
}