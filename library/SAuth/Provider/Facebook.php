<?php

/**
 * Authorisation with facebook
 */
class SAuth_Provider_Facebook {
    
    /**
     * @var array Configuration array
     */
    protected $_config = array(
        'consumerKey' => '',
        'consumerSecret' => '',
        'requestTokenUrl' => 'http://www.facebook.com/dialog/oauth',
        'accessTokenUrl' => 'https://graph.facebook.com/oauth/access_token',
        'clientId' => '184454904920383',
        'redirectUri' => 'http://dnixa.tmweb.ru/index/auth/',
    );
    
    /**
     * @var bool Auth flag
     */
    protected $_isAuthorized = false;
    
    /**
     * @var int Authentication identification
     */
    protected $_id = null;
    
    /**
     * @var string Session key
     */
    protected $_sessionKey = 'SAUTH_FACEBOOK';
    
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
     * Getting authentication identification
     * @return false|int User ID
     */
    public function getAuthId() {
        
        $id = (int) $this->getUserParam('user_id');
        return $id > 0 ? $id : false;
    }
    
    /**
     * Returns token params
     * @param string $key
     * @return mixed
     */
    public function getUserParam($key = null) {
        
        $tokenAccess = $this->_getTokenAccess();
        if (!empty($tokenAccess)) {
            
            if ($key != null) {
                $key = (string) $key;
                return $tokenAccess->getParam($key);
            }
        }
        return false;
    }
    
    /**
     * Authorized user by facebook OAuth 2.0
     * @param array $config
     * @return true
     */
    public function auth(array $config = array()) {
        
        $config = $this->setConfig($config);
        $consumer = new Zend_Http_Client();
        
        if (isset($_GET['code'])) {
            $code = $_GET['code'];
        
            $consumer->setUri($config['accessTokenUrl']);
            $array = array(
                'client_id' => $config['clientId'],
                'redirect_uri' => $config['redirectUri'],
                'client_secret' => $config['consumerSecret'],
                'code' => $code,
                'scope' => 'email',
            );
            $consumer->setParameterPost($array);
            $response = $consumer->request(Zend_Http_Client::POST);
            $this->_setTokenAccess(Zend_Json::decode($response->getBody()));
            var_dump($response->getBody());
            return true;
        } else {
            $url = $config['requestTokenUrl'] . '?';
            $url .= http_build_query(array('client_id' => $config['clientId'], 'redirect_uri' => $config['redirectUri'], 'scope' => 'email'), null, '&');
            header('Location: '.$url);
        }
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
            throw new SAuth_Exception('Invalid twitter auth storage key');
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
            return $this->_config[$key];
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
     * Trying get token request from session storage
     * @return false|string
     */
    protected function _getTokenRequest() {
        
        $sessionStorage = $this->getSessionStorage();
        return !empty($sessionStorage->tokenRequest) ? unserialize($sessionStorage->tokenRequest) : false;
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
     * Setting token request from session storage
     * @param string $tokenRequest
     * @return string
     */
    protected function _setTokenRequest($tokenRequest) {
        
        $sessionStorage = $this->getSessionStorage();
        return $sessionStorage->tokenRequest = serialize($tokenRequest);
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
     * Unset token request from session storage
     */
    protected function _unsetTokenRequest() {
        
        $sessionStorage->tokenRequest = null;
        unset($sessionStorage->tokenRequest);
    }

    /**
     * Unset token access from session storage
     */
    protected function _unsetTokenAccess() {
            
        $sessionStorage->tokenAccess = null;
        unset($sessionStorage->tokenAccess);
    }
}