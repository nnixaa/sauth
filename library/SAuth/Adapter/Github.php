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
     * @var array Configuration array
     */
    protected $_config = array(
        'consumerId'            => '',
        'consumerSecret'        => '',
        'callbackUrl'           => '',
        'userAuthorizationUrl'  => 'https://github.com/login/oauth/authorize',
        'accessTokenUrl'        => 'https://github.com/login/oauth/access_token',
        'requestDatarUrl'       => 'https://github.com/api/v2/json/user/show',
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
                //gowalla return 400 http code on error
                switch  ($response->getStatus()) {
                    case '400':
                        $parsedErrors = $this->parseResponseJson($response->getBody());
                        $error = $parsedErrors['detail'];
                        break;
                    default:
                        $error = 'Github Oauth service unavailable';
                        break;
                }

                return new Zend_Auth_Result(Zend_Auth_Result::FAILURE, false, array($error));
                
            } elseif ($response->isSuccessful()) {
                
                $parsedResponse = $this->parseResponseJson($response->getBody());
                
                $identity = $this->_prepareIdentity($parsedResponse);
                
                return new Zend_Auth_Result(Zend_Auth_Result::SUCCESS, $identity);
                
            }
        } elseif (!isset($_GET['error'])) {
            
            $authorizationConfig = array(
                'client_id'     => $clientId, 
                'redirect_uri'  => $redirectUrl,
            );

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
        
    }
    
}