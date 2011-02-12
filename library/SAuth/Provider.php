<?php

/**
 * SAuth Provider
 */
class SAuth_Provider {
    
    const FACEBOOK = 'SAuth_Provider_Facebook';
    const TWITTER = 'SAuth_Provider_Twitter';
    const GOOGLE = 'SAuth_Provider_Google';
    const FOURSQUARE = 'SAuth_Provider_Foursquare';
    const MAILRU = 'SAuth_Provider_Mailru';
    const VKONTAKTE = 'SAuth_Provider_Vkontakte';
    
    /**
     * @var Zend_Session_Namespace
     */
    protected $_currentProviderStorage = null;
    
    /**
     * @var string Current provider class name
     */
    protected static $_currentProviderName = '';
    
    /**
     * @var SAuth_Provider
     */
    protected static $_currentProviderObject = null;
    
    /**
     * @var bool
     */
    protected $_isSetuped = false;
    
    /**
     * Object constructor method
     */
    public function __construct() {
        
        $this->_currentProviderStorage = new Zend_Session_Namespace('SAUTH_PROVIDER');
        
        if (!empty($this->_currentProviderStorage->className)) {
                
            $this->setUpProvider($this->_currentProviderStorage->className, $this->_currentProviderStorage->configuration);
        }
    }
    
    /**
     * Check auth
     * @return bool 
     */
    public function isAuthorized() {
        
        if ($this->isSetuped() && $this->getCurrentProvider()->isAuthorized()) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Setup provider
     * @param string $class
     * @param array $configuration
     * @return Sauth_Providre|false
     */
    public function setUpProvider($class, array $configuration = array()) {
        
        $this->setCurrentProviderName($class);
        
        Zend_Loader::loadClass($class);
        $provider = new $class();
        
        if ($provider instanceof SAuth_Provider_Interface) {
            
            $provider->setConfig($configuration);
            
            $this->_currentProviderStorage->configuration = $configuration;
            $this->_currentProviderStorage->className = $class;
            
            $this->_isSetuped = true;
            
            return $this->_currentProviderObject = $provider;
        }
        return false;
    }
    
    /**
     * Check is provider class has been setuped
     * @return bool
     */
    public function isSetuped() {
        
        return $this->_isSetuped;
        
    }
    
    /**
     * Authenticate user
     * @return bool
     */
    public function authenticate() {
        
        if (!$this->isSetuped()) {
            throw new SAuth_Exception('You should run setUpProvider() before authenticate');
        }
        return $this->getCurrentProvider()->authenticate();
    }
    
    /**
     * Returns current provider object
     * @var Sauth_provider
     */
    public function getCurrentProvider() {
        
        $provider = $this->_currentProviderObject;
        return $provider;
    }
    
    /**
     * Return current provider class name
     * @return string
     */
    public function getCurrentProviderName() {
        
        return $this->_currentProviderName;
    }

    /**
     * Sets current provider class name
     * @return string
     */
    public function setCurrentProviderName($class) {
        
        $class = (string) $class;
        return $this->_currentProviderName = $class;
    }
    
}
