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
 * Authentication with foursquare
 * 
 * http://developer.foursquare.com/docs/oauth.html
 */
class SAuth_Adapter_Foursquare extends SAuth_Adapter_Abstract implements Zend_Auth_Adapter_Interface {

    
    /**
     * Response types
     */
    const RESPONSE_TYPE_CODE        = 'code';
    const RESPONSE_TYPE_TOKEN       = 'token';
    const RESPONSE_TYPE_CODE_TOKEN  = 'code_and_token';
    
    /**
     * Grant type
     */
    const GRANT_TYPE = 'authorization_code';
        
    /**
     * @var array Configuration array
     */
    protected $_config = array(
        'consumerId'            => '',
        'consumerSecret'        => '',
        'callbackUrl'           => '',
        'userAuthorizationUrl'  => 'https://foursquare.com/oauth2/authorize',
        'accessTokenUrl'        => 'https://foursquare.com/oauth2/access_token',
        'requestDatarUrl'       => 'https://api.foursquare.com/v2/users/self',
        'responseType'          => self::RESPONSE_TYPE_CODE,
        'grantType'             => self::GRANT_TYPE,
    );
    
    /**
     * @var string Session key
     */
    protected $_sessionKey = 'SAUTH_FOURSQUARE';
    
    /**
     * Authenticate user by foursquare OAuth 2.0
     * @return Zend_Auth_Result
     */
    public function authenticate() {
        
        $config = $this->getConfig();
        
        $authorizationUrl   = $config['userAuthorizationUrl'];
        $accessTokenUrl     = $config['accessTokenUrl'];
        $clientId           = $config['consumerId'];
        $clientSecret       = $config['consumerSecret'];
        $redirectUrl        = $config['callbackUrl'];
        $responseType       = $config['responseType'];
        $grantType          = $config['grantType'];
        
        if (empty($authorizationUrl) || empty($clientId) || empty($clientSecret) || empty($redirectUrl) 
            || empty($accessTokenUrl)) {
                
            require_once 'Zend/Auth/Adapter/Exception.php';
            throw new Zend_Auth_Adapter_Exception('Foursquare auth configuration not specifed');
        }
        
        if (isset($_GET['code']) && !empty($_GET['code'])) {
            	
            $accessConfig = array(
                'client_id'     => $clientId,
                'redirect_uri'  => $redirectUrl,
                'client_secret' => $clientSecret,
                'code'          => trim($_GET['code']),
                'grant_type'    => $grantType,

            );
            
            $response = $this->httpRequest('POST', $accessTokenUrl, $accessConfig);
            
            if ($response->isError()) {
                //foursquare return 400 http code on error
                switch  ($response->getStatus()) {
                    case '400':
                        $parsedErrors = $this->parseResponseJson($response->getBody());
                        $error = $parsedErrors['error'];
                        break;
                    default:
                        $error = 'Foursquare Oauth service unavailable';
                        break;
                }

                return new Zend_Auth_Result(Zend_Auth_Result::FAILURE, false, array($error));
                
            } elseif ($response->isSuccessful()) {
                
                $parsedResponse = $this->parseResponseJson($response->getBody());

                //try to get user data
                $userParameters = (array) $this->requestUserParams($parsedResponse['access_token']);
                
                $identity = $this->_prepareIdentity(array_merge($parsedResponse, $userParameters));
                
                return new Zend_Auth_Result(Zend_Auth_Result::SUCCESS, $identity);
                
            }
        } elseif (!isset($_GET['error'])) {
            
            $authorizationConfig = array(
                'client_id'     => $clientId, 
                'redirect_uri'  => $redirectUrl,
                'response_type' => $responseType,
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
     * Request user params on foursquare
     * @return array User params
     */
    public function requestUserParams($accessToken) {
        
        $apiUrl = $this->getConfig('requestDatarUrl');

        if ($accessToken && !empty($apiUrl)) {
            
            $response = $this->httpRequest('GET', $apiUrl, array('oauth_token' => $accessToken));
            
            if ($response->isError()) {
                // TODO: maybe will better return an error?
                // $parsedErrors = (array) $this->parseResponseJson($response->getBody());
                return false;
            } elseif ($response->isSuccessful()) {
                $parsedResponse = (array) $this->parseResponseJson($response->getBody());
                return isset($parsedResponse['response']['user']) ? $parsedResponse['response']['user'] : false;
            }
        }
        return false;
    }
    
}