<?php

/**
 * Authorisation with google
 */
class SAuth_Provider_Google {

    /**
     * @var array Configuration array
     */
    protected $_config = array(
        'id' => 'https://www.google.com/accounts/o8/id',
        'callbackUrl' => '',
        'exchangeExtension' => array(),
        'root' => '',
    );
    
    /**
     * @var string Session key
     */
    protected $_sessionKey = 'SAUTH_GOOGLE';
    
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
        
        $accessParams = $this->_getAccessParams();
        return empty($accessParams) ? false : true;
    }    

    /**
     * Getting authentication identification
     * @return false|int User ID
     */
    public function getAuthId() {
        
        $id = (string) $this->getUserParam('openid_identity');
        return !empty($id) ? $id : false;
    }
    
    /**
     * Returns token params
     * @param string $key
     * @return mixed
     */
    public function getUserParam($key = null) {
        
        $accessParams = $this->_getAccessParams();
        if (!empty($accessParams)) {
            
            if ($key != null) {
                $key = (string) $key;
                return $accessParams[$key];
            }
        }
        return false;
    }
    
    /**
     * Authorized user by google OpenId
     * @param array $config
     * @return true
     */
    public function auth(array $config = array()) {
        
        $config = $this->setConfig($config);
        if (!isset($config['id']) || empty($config['id'])) {
            throw new SAuth_Exception('Invalid google OpenId url');
        }
        $consumer = new Ak33m_OpenId_Consumer();
        $googleExt = new SAuth_Provider_Google_Extension();
        
        if (is_array($config['exchangeExtension']) && !empty($config['exchangeExtension'])) {
            $googleExt->setParams($config['exchangeExtension']);
        }
        if (!isset($_GET['openid_mode']) || empty($_GET['openid_mode'])) {
            $consumer->login($config['id'], $config['callbackUrl'], $config['root'], $googleExt);
            if ($error = $consumer->getError()) {
                throw new SAuth_Exception($error);
            }
        } elseif (isset($_GET['openid_mode']) && $_GET['openid_mode'] == 'id_res') {
                
            if ($consumer->verify($_GET, $id, $googleExt)) {
                $this->_setAccessParams($_GET);
                return $this->isAuthorized();
            } else {
                return false;
            }
        }
        return false;
        
    }
    
    /**
     * Trying get response from session storage
     * @return false|string
     */
    protected function _getAccessParams() {
        
        $sessionStorage = $this->getSessionStorage();
        return !empty($sessionStorage->accessParams) ? unserialize($sessionStorage->accessParams) : false;
    }

    /**
     * Setting response
     * @return false|string
     */
    protected function _setAccessParams($accessParams) {
        
        $sessionStorage = $this->getSessionStorage();
        return $sessionStorage->accessParams = serialize($accessParams);
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
            throw new SAuth_Exception('Invalid google auth storage key');
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
}