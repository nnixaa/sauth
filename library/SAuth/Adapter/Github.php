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
 * Authentication with github
 * 
 * http://develop.github.com/p/oauth.html
 */
class SAuth_Adapter_Github extends SAuth_Adapter_Abstract implements Zend_Auth_Adapter_Interface {

    /**
     * Scopes let you specify exactly what type of access you need
     */
    const SCOPE_USER        = 'user';
    const SCOPE_PUBLIC_REPO = 'public_repo';
    const SCOPE_REPO        = 'repo';
    const SCOPE_GIST        = 'gist';
    
    /**
     * @var array Configuration array
     */
    protected $_config = array(
        'consumerId'            => '',
        'consumerSecret'        => '',
        'callbackUrl'           => '',
        'userAuthorizationUrl'  => 'https://github.com/login/oauth/authorize',
        'accessTokenUrl'        => 'https://github.com/login/oauth/access_token',
        'requestDatarUrl'       => 'https://github.com/api/v2/json/user/show',
        'scope'                 => array(
            self::SCOPE_USER
         ),
    );
    
    /**
     * @var string Session key
     */
    protected $_sessionKey = 'SAUTH_GITHUB';
    
    /**
     * Authenticate user by github OAuth 2.0
     * @return Zend_Auth_Result
     */
    public function authenticate() {
        
        $config = $this->getConfig();
        
        $authorizationUrl   = $config['userAuthorizationUrl'];
        $accessTokenUrl     = $config['accessTokenUrl'];
        $clientId           = $config['consumerId'];
        $clientSecret       = $config['consumerSecret'];
        $redirectUrl        = $config['callbackUrl'];
        
        if (empty($authorizationUrl) || empty($clientId) || empty($clientSecret) || empty($redirectUrl) 
            || empty($accessTokenUrl)) {
                
            require_once 'Zend/Auth/Adapter/Exception.php';
            throw new Zend_Auth_Adapter_Exception('Github auth configuration not specifed');
        }
        
        if (isset($_GET['code']) && !empty($_GET['code'])) {
            	
            $accessConfig = array(
                'client_id'     => $clientId,
                'redirect_uri'  => $redirectUrl,
                'client_secret' => $clientSecret,
                'code'          => trim($_GET['code']),
            );
            
            $response = $this->httpRequest('POST', $accessTokenUrl, $accessConfig);
            
            if ($response->isError()) {
                    
                $error = 'Github Oauth service unavailable';
                return new Zend_Auth_Result(Zend_Auth_Result::FAILURE, false, array($error));
                
            } elseif ($response->isSuccessful()) {

                $parsedResponse = $this->parseResponseUrl($response->getBody());
                
                if (isset($parsedResponse['error'])) {
                    
                    return new Zend_Auth_Result(Zend_Auth_Result::FAILURE, false, array($parsedResponse['error']));
                }
                
                //try to get user data
                $userParameters = (array) $this->requestUserParams($parsedResponse['access_token']);
                
                $identity = $this->_prepareIdentity(array_merge($parsedResponse, $userParameters));

                return new Zend_Auth_Result(Zend_Auth_Result::SUCCESS, $identity);
                
            }
        } elseif (!isset($_GET['error'])) {
            
            $authorizationConfig = array(
                'client_id'     => $clientId, 
                'redirect_uri'  => $redirectUrl,
            );
            
            if (isset($config['scope']) && !empty($config['scope'])) {
                $authorizationConfig['scope'] = implode($config['scope'], ',');
            }
            
            $url = $authorizationUrl . '?';
            $url .= http_build_query($authorizationConfig, null, '&');
            header('Location: ' . $url);
            exit(1);
            
        } else {
            
            return new Zend_Auth_Result(Zend_Auth_Result::FAILURE, false, array($_GET['error']));
            
        }
        
    }
    
    /**
     * Request user params on github
     * @return array User params
     */
    public function requestUserParams($accessToken) {
        
        $apiUrl = $this->getConfig('requestDatarUrl');

        if ($accessToken && !empty($apiUrl)) {
            
            $response = $this->httpRequest('GET', $apiUrl, array('access_token' => $accessToken));
            
            if ($response->isError()) {
                // TODO: maybe will better return an error?
                // $parsedErrors = (array) $this->parseResponseJson($response->getBody());
                return false;
            } elseif ($response->isSuccessful()) {
                $parsedResponse = (array) $this->parseResponseJson($response->getBody());
                return $parsedResponse;
            }
        }
        return false; 
    }
    
}