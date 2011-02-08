<?php

/**  SAuth_Provider_Abstract */
require_once 'SAuth/Provider/Abstract.php';

/**  SAuth_Provider_Interface */
require_once 'SAuth/Provider/Interface.php';

/**  Zend_Oauth_Consumer */
require_once 'Zend/Oauth/Consumer.php';


/**
 * Authorisation with twitter
 * http://developer.twitter.com/pages/auth
 */
class SAuth_Provider_Twitter extends SAuth_Provider_Abstract implements SAuth_Provider_Interface {
    
    /**
     * @var array Configuration array
     */
    protected $_config = array(
        'requestScheme' => Zend_Oauth::REQUEST_SCHEME_HEADER,
        'consumerKey' => '',
        'consumerSecret' => '',
        'version' => '1.0',
        'callbackUrl' => '',
        'requestTokenUrl' => 'https://api.twitter.com/oauth/request_token',
        'userAuthorizationUrl' => 'https://api.twitter.com/oauth/authorize',
        'accessTokenUrl' => 'https://api.twitter.com/oauth/access_token',
    );
    
    /**
     * @var string Session key
     */
    protected $_sessionKey = 'SAUTH_TWITTER';
    
    /**
     * Authorized user by twitter OAuth
     * @param array $config
     * @return true
     */
    public function auth(array $config = array()) {
        
        if ($this->isAuthorized()) {
            return true;
        }
        
        $config = $this->setConfig($config);
        if (empty($config['consumerKey']) || empty($config['consumerSecret']) || empty($config['userAuthorizationUrl']) 
            || empty($config['accessTokenUrl']) || empty($config['callbackUrl'])) {
                
            require_once 'SAuth/Exception.php';
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
    
}