<?php

/**  Zend_Session_Namespace */
require_once 'Zend/Session/Namespace.php';

/**
 * Abstract class for Sauth libraries
 */
abstract class SAuth_Adapter_Abstract {
    
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
    public function __construct(array $config) {
        
        $this->setConfig($config);
        $this->setUpSessionStorage();
    }
      
    /**
     * TODO: Can't select multi-level arrays
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
     * Setting up session storage
     * @return Zend_Session_Namespace
     */
    public function setUpSessionStorage() {
        
        $sessionKey = (string) $this->getSessionKey();
        if (empty($sessionKey)) {
            require_once 'SAuth/Exception.php';
            throw new SAuth_Exception('Invalid auth storage key.');
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
     * Getting session key
     * @return string
     */
    public function getSessionKey() {
        
        return $this->_sessionKey;
    }

    /**
     * Gettion session live time
     * @return int
     */
    public function getSessionLiveTime() {

        return $this->_sessionLiveTime;
    }
    
    /**
     * Setting configuration
     * @param array $config
     * @return array Configuration array
     */
    public function setConfig(array $config) {
            
        foreach ($config as $key => $value) {
        	
            switch ($key) {
                case 'sessionKey':
                    $this->_setSessionKey($value);
                    unset($config[$key]);
                    break;
					
                case 'sessionLiveTime':
                    $this->_setSessionLiveTime($value);
                    unset($config[$key]);
					
                default:
					$this->_config[$key] = $value;
                    break;
            }
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
     * Parse response url
     * @param string $url
     * @return array|false
     */
    public function parseResponseUrl($url) {

        $url = (string) trim($url);
        $pairs = explode('&', $url);
        
        $parsed = array();
        foreach ($pairs as $pair) {
            list($key, $value) = explode('=', $pair, 2);
            if (!empty($key) && !empty($value)) {
                $parsed[$key] = $value;
            }
        }
        return empty($parsed) ? false : $parsed;
    }
    
    /**
     * Parse response json
     * @param string $body
     * @return array|false
     */
    public function parseResponseJson($body) {
            
        $body = (string) trim($body);
        return Zend_Json::decode($body);
    }    
    
    /**
     * Send http request
     * @param string $type GET or POST
     * @param string $url 
     * @param string $parameters
     * @return Zend_Http_Response
     */
    public function httpRequest($type, $url, $parameters) {
        
        $client = new Zend_Http_Client();
        $client->setUri($url);
        
        if ($type == Zend_Http_Client::GET) {
            
            $client->setParameterGet($parameters);
            
        } elseif ($type == Zend_Http_Client::POST) {
            
            $client->setParameterPost($parameters);
        }
        
        return $client->request($type);
    }  
    
    /** 
     * Setting session key
     * After setSession key you must reset session storage calling setUpSessionStorage
     * @param string $key 
     * @return false|string
     */
    protected function _setSessionKey($key) {
        
        $key = (string) $key;
        if (!empty($key)) {
            return $this->_sessionKey = $key;
        }
        return false;
    }	
	
    /**
     * Settion session live time
     * @param int $time
     * @return false|int
     */
    protected function _setSessionLiveTime($time) {
        if ($time > 0) {
            return $this->_sessionLiveTime = (int) $time;
        }
        return false;
    }	
	
    /**
     * Getting token access from session storage
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
    
    /**
     * Getting token request from session storage
     * @return false|string
     */
    protected function _getTokenRequest() {
        
        $sessionStorage = $this->getSessionStorage();
        return !empty($sessionStorage->tokenRequest) ? unserialize($sessionStorage->tokenRequest) : false;
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
     * Unset token request from session storage
     */
    protected function _unsetTokenRequest() {
        
        $sessionStorage->tokenRequest = null;
        unset($sessionStorage->tokenRequest);
    }
}
