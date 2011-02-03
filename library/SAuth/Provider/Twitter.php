<?php

/**
 * Authorisation with twitter
 */
class SAuth_Provider_Twitter {
    
    /**
     * @var array Configuration array
     */
    protected $_config = array(
        'requestScheme' => Zend_Oauth::REQUEST_SCHEME_HEADER,
        'consumerKey' => '',
        'consumerSecret' => '',
        'version' => '1.0',
        'requestTokenUrl' => 'https://api.twitter.com/oauth/request_token',
        'userAuthorizationUrl' => 'https://api.twitter.com/oauth/authorize',
        'accessTokenUrl' => 'https://api.twitter.com/oauth/access_token',
        'callbackUrl' => 'http://dnixa.tmweb.ru/index/auth',
    );
    
    /**
     * @var string Session key
     */
    protected $_sessionKey = 'SAUTH_TWITTER';
    
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
     * Authorized user by twitter OAuth
     * @param array $config
     * @return true
     */
    public function auth(array $config = array()) {
        
        $config = $this->setConfig($config);
        if (empty($config['consumerKey']) || empty($config['consumerSecret']) || empty($config['userAuthorizationUrl']) 
            || empty($config['accessTokenUrl']) || empty($config['callbackUrl'])) {
                
            throw new SAuth_Exception('Twitter auth configuration not specifed.');
        }
        
        $consumer = new Zend_Oauth_Consumer($config);
        $tokenRequest = $this->_getTokenRequest();
        
        if (!empty($tokenRequest) && !empty ($_GET)) {
            $tokenAccess = $consumer->getAccessToken($_GET, $tokenRequest);
            $response = $tokenAccess->getResponse();
            
            if ($response->isError()) {
                switch  ($response->getStatus()) {
                    case '400':
                        $error = 'Error has occurred.';
                        break;
                    default:
                        $error = 'OAuth service unavailable.';
                        break;
                }
                return false;
            } elseif ($response->isSuccessful()) {
                $parsedResponse = $this->_parseResponse($response->getBody());
                $this->_setTokenAccess($parsedResponse['oauth_token']);
                $this->setUserParameters($parsedResponse);
                $this->_unsetTokenRequest();
                return $this->isAuthorized();
            }
            return false;
            
        } else {
            $tokenRequest = $consumer->getRequestToken();
            $this->_setTokenRequest($tokenRequest);
            $consumer->redirect();
        }
    }

    /**
     * Getting authentication identification
     * @return false|int User ID
     */
    public function getAuthId() {
        
        $id = (int) $this->getUserParameters('user_id');
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
                return $userParameters[$key];
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
        $sessionStorage = $this->getSessionStorage();
        return $sessionStorage->userParameters = $userParameters;
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
                    list($key, $value) = explode('=', $pair);
                    $parsed[$key] = $value;
                }
            }
            return $parsed;
        }
        return false;
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