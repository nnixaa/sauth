<?php

/**  
 * @see SAuth_Adapter_Abstract 
 */
require_once 'SAuth/Adapter/Abstract.php';

/**
 * @see Zend_Auth_Adapter_Interface
 */
require_once 'Zend/Auth/Adapter/Interface.php';

/**  
 * @see Zend_Oauth_Consumer 
 */
require_once 'Zend/Oauth/Consumer.php';


/**
 * Authentication with Skyrock.com
 * 
 * http://www.skyrock.com/developer/documentation/
 */
class SAuth_Adapter_Skyrock extends SAuth_Adapter_Abstract implements Zend_Auth_Adapter_Interface {
    
    /**
     * @var array Configuration array
     */
    protected $_config = array(
        'requestScheme'         => Zend_Oauth::REQUEST_SCHEME_HEADER,
        'consumerKey'           => '',
        'consumerSecret'        => '',
        'version'               => '1.0',
        'callbackUrl'           => '',
        'requestTokenUrl'       => 'https://api.skyrock.com/v2/oauth/initiate',
        'userAuthorizationUrl'  => 'https://api.skyrock.com/v2/oauth/authenticate',
        'accessTokenUrl'        => 'https://api.skyrock.com/v2/oauth/token',
    );
    
    /**
     * @var string Session key
     */
    protected $_sessionKey = 'SAUTH_SKYROCK';
    
    /**
     * Authenticate user by Skyrock OAuth
     * @return Zend_Auth_Result
     */
    public function authenticate() {
        
        $config = $this->getConfig();
        
        if (empty($config['consumerKey']) || empty($config['consumerSecret']) || empty($config['userAuthorizationUrl']) 
            || empty($config['accessTokenUrl']) || empty($config['callbackUrl'])) {
                
            require_once 'Zend/Auth/Adapter/Exception.php';
            throw new Zend_Auth_Adapter_Exception('Skyrock auth configuration not specifed');
        }
        
        $consumer = new Zend_Oauth_Consumer($config);
        $tokenRequest = $this->_getTokenRequest();
        
        if (!empty($tokenRequest) && !empty ($_GET)) {
            
            $tokenAccess = $consumer->getAccessToken($_GET, $tokenRequest);
            $response = $tokenAccess->getResponse();
            
            if ($response->isError()) {
                //TODO:change on custom
                $error = 'Skyrock Oauth service unavailable';
                return new Zend_Auth_Result(Zend_Auth_Result::FAILURE, false, array($error));
               
            } elseif ($response->isSuccessful()) {

                $parsedResponse = $this->parseResponseUrl($response->getBody());

                $this->_unsetTokenRequest();
                
                $identity = $this->_prepareIdentity($parsedResponse);
                
                return new Zend_Auth_Result(Zend_Auth_Result::SUCCESS, $identity);
            }
            
        } else {
            
            $tokenRequest = $consumer->getRequestToken();
            $this->_setTokenRequest($tokenRequest);
            $consumer->redirect();
        }
    }
    
}
