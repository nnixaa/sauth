<?php

/**
 * Authorisation with mail.ru
 * http://api.mail.ru/docs/guides/oauth/sites/
 * http://api.mail.ru/sites/my/
 */
class SAuth_Provider_Mailru {
    
    /**
     * @var array Configuration array
     */
    protected $_config = array(
        'privateKey' => '',
        'consumerSecret' => '',
        'clientId' => '',
        'redirectUri' => '',
        'userAuthorizationUrl' => 'https://connect.mail.ru/oauth/authorize',
        'accessTokenUrl' => 'https://connect.mail.ru/oauth/token',
        'responseType' => 'code',
        'restUrl' => 'http://www.appsmail.ru/platform/api'
    );
    
    /**
     * @var string Session key
     */
    protected $_sessionKey = 'SAUTH_MAILRU';
    
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
     * Authorized user by facebook OAuth 2.0
     * @param array $config
     * @return true
     */
    public function auth(array $config = array()) {
        
        $config = $this->setConfig($config);
        
        $authorizationUrl = $config['userAuthorizationUrl'];
        $accessTokenUrl = $config['accessTokenUrl'];
        $clientId = $config['clientId'];
        $clientSecret = $config['consumerSecret'];
        $privateKey = $config['privateKey'];
        $redirectUrl = $config['redirectUri'];
        $responseType = $config['responseType'];
        
        if (empty($authorizationUrl) || empty($clientId) || empty($clientSecret) || empty($redirectUrl) 
            || empty($accessTokenUrl) || empty($privateKey)) {
            throw new SAuth_Exception('Mail.ru auth configuration not specifed.');
        }

        if (isset($_GET['code']) && !empty($_GET['code'])) {
            	
            $authorizationCode = trim($_GET['code']);
            $accessConfig = array(
                'client_id' => $clientId,
                'redirect_uri' => $redirectUrl,
                'client_secret' => $clientSecret,
                'code' => $authorizationCode,
                'grant_type' => 'authorization_code',
            );
            
            $client = new Zend_Http_Client();
            $client->setUri($accessTokenUrl);
            $client->setParameterPost($accessConfig);
            $response = $client->request(Zend_Http_Client::POST);
            if ($response->isError()) {
                $error = 'OAuth service unavailable.';
                return false;
                
            } elseif ($response->isSuccessful()) {
                
                $parsedResponse = $this->_parseResponse($response->getBody());
                $this->_setTokenAccess($parsedResponse['access_token']);
                $this->setUserParameters($parsedResponse);
                if ($userParameters = $this->requestUserParams()) {
                    $this->setUserParameters($userParameters);
                }
                return $this->isAuthorized();
            }
        } else {
            
            $authorizationConfig = array(
                'client_id' => $clientId, 
                'redirect_uri' => $redirectUrl,
                'response_type' => $responseType,
            );
            // TODO: maybe http_build_url ?
            $url = $authorizationUrl . '?';
            $url .= http_build_query($authorizationConfig, null, '&');
            header('Location: ' . $url);
            exit(1);
        }
    }
    
    /**
     * Getting authentication identification
     * @return false|int User ID
     */
    public function getAuthId() {
        
        $id = (int) $this->getUserParameters('uid');
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
     * Request user params on mail.ru using REST API
     * FIXME: Working only after auth process, because don't consider expire time
     * @return array User params
     */
    public function requestUserParams() {
        
        $restUrl = $this->getConfig('restUrl');
        $accessToken = $this->_getTokenAccess();
        $config = $this->getConfig();
        
        if ($accessToken && !empty($restUrl)) {
            $client = new Zend_Http_Client();
            $client->setUri($restUrl);
            $requestParametrs = array(
                'app_id' => $config['clientId'],
                'method' => 'users.getInfo',
                'secure' => 1,
                'session_key' => $accessToken,
            );
            $sig = $this->getSign($requestParametrs);
            $requestParametrs['sig'] = $sig;
            
            $client->setParameterPOST($requestParametrs);
            $response = $client->request(Zend_Http_Client::POST);
            if ($response->isError()) {
                $parsedErrors = (array) Zend_Json::decode($response->getBody());
                $error = $parsedErrors['error']['error_msg'];
                return false;
            } elseif ($response->isSuccessful()) {
                $parsedResponse = (array) Zend_Json::decode($response->getBody());
                return isset($parsedResponse[0]) ? $parsedResponse[0] : false;
            }
        }
        return false;
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
        if ($key != null) {
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
     * Parse response
     * @param string $body
     * @return array|false
     */
    protected function _parseResponse($body) {
        
        if (is_string($body) && !empty($body)) {
            return Zend_Json::decode($body);
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
    
    /**
     * Return mail.ru sign
     * @param array $requestParams Request parameters
     * @return string Signature
     */
    protected function getSign(array $requestParams) {
        
        $config = $this->getConfig();
        $uid = $this->_getTokenAccess();
        $privateKey = $config['privateKey'];
        
        ksort($requestParams);
        $params = '';
        foreach ($requestParams as $key => $value) {
            $params .= $key . '=' . $value;
        }
        return md5($params . $privateKey);
    }
}