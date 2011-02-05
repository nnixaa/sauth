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
        'clientId' => '',
        'redirectUri' => '',
        'userAuthorizationUrl' => 'http://www.facebook.com/dialog/oauth',
        'accessTokenUrl' => 'https://graph.facebook.com/oauth/access_token',
        'graphUrl' => 'https://graph.facebook.com',
        'scope' => null,
    );
    
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
        $redirectUrl = $config['redirectUri'];
        
        if (empty($authorizationUrl) || empty($clientId) || empty($clientSecret) || empty($redirectUrl) || empty($accessTokenUrl)) {
            throw new SAuth_Exception('Facebook auth configuration not specifed.');
        }
        if (isset($config['scope']) && !empty($config['scope'])) {
            $scope = $config['scope'];
        }
        
        if (isset($_GET['code']) && !empty($_GET['code'])) {
            	
            $authorizationCode = trim($_GET['code']);
            $accessConfig = array(
                'client_id' => $clientId,
                'redirect_uri' => $redirectUrl,
                'client_secret' => $clientSecret,
                'code' => $authorizationCode,
                'scope' => implode($scope, ','),
            );
            
            $client = new Zend_Http_Client();
            $client->setUri($accessTokenUrl);
            $client->setParameterPost($accessConfig);
            $response = $client->request(Zend_Http_Client::POST);
            
            if ($response->isError()) {
                //facebook return 400 http code on error
                switch  ($response->getStatus()) {
                    case '400':
                        $jsonError = Zend_Json::decode($response->getBody());
                        $error = $jsonError['error']['message'];
                        break;
                    default:
                        $error = 'OAuth service unavailable.';
                        break;
                }
                return false;
            } elseif ($response->isSuccessful()) {
                
                $parsedResponse = $this->_parseResponse($response->getBody());
                $this->_setTokenAccess($parsedResponse['access_token']);
                //try to get user data
                if ($userParameters = $this->requestUserParams()) {
                    $this->setUserParameters($userParameters);
                }
                return $this->isAuthorized();
            }
        } else {
            
            $authorizationConfig = array(
                'client_id' => $clientId, 
                'redirect_uri' => $redirectUrl,
            );
            if (isset($scope)) {
                $authorizationConfig['scope'] = implode($scope, ',');
            }
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
     * Request user params on facebook using Graph API
     * @return array User params
     */
    public function requestUserParams() {
        
        if (!$this->isAuthorized()) {
            return false;
        }
        
        $graphUrl = $this->getConfig('graphUrl');
        $accessToken = $this->_getTokenAccess();

        if ($accessToken && !empty($graphUrl)) {
            $client = new Zend_Http_Client();
            $url = $graphUrl . '/me';
            $client->setUri($url);
            $client->setParameterGET(array('access_token' => $accessToken));
            $response = $client->request(Zend_Http_Client::GET);
            if ($response->isError()) {
                $error = 'Request user parameters failed.';
                return false;
            } elseif ($response->isSuccessful()) {
                return Zend_Json::decode($response->getBody());
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