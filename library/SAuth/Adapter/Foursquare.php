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
     * @var array Configuration array
     */
    protected $_config = array(
        'consumerId' => '',
        'consumerKey' => '',
        'consumerSecret' => '',
        'callbackUrl' => '',
        'userAuthorizationUrl' => 'https://foursquare.com/oauth2/authorize',
        'accessTokenUrl' => 'https://foursquare.com/oauth2/access_token',
        'requestDatarUrl' => 'https://api.foursquare.com/v2/users/self',
        'responseType' => 'code',
        
    );
    
    /**
     * @var string Session key
     */
    protected $_sessionKey = 'SAUTH_FOURSQUARE';
    
    /**
     * Authenticate user by foursquare OAuth 2.0
     * @return true
     */
    public function authenticate() {
        
        $config = $this->getConfig();
        
        $authorizationUrl = $config['userAuthorizationUrl'];
        $accessTokenUrl = $config['accessTokenUrl'];
        $clientId = $config['consumerId'];
        $clientSecret = $config['consumerSecret'];
        $redirectUrl = $config['callbackUrl'];
        $responseType = $config['responseType'];
        
        if (empty($authorizationUrl) || empty($clientId) || empty($clientSecret) || empty($redirectUrl) 
            || empty($accessTokenUrl)) {
                
            require_once 'SAuth/Exception.php';
            throw new SAuth_Exception('Foursquare auth configuration not specifed.');
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
                $userParameters = $this->requestUserParams($parsedResponse['access_token']);
                
                return new Zend_Auth_Result(Zend_Auth_Result::SUCCESS, array_merge($parsedResponse, $userParameters));
                
            }
        } elseif (!isset($_GET['error'])) {
            
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
        } else {
            
            return new Zend_Auth_Result(Zend_Auth_Result::FAILURE, false, array($_GET['error']));
            
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
     * Request user params on foursquare
     * @return array User params
     */
    public function requestUserParams($accessToken) {
        
        $apiUrl = $this->getConfig('requestDatarUrl');

        if ($accessToken && !empty($apiUrl)) {
            
            $response = $this->httpRequest('GET', $apiUrl, array('oauth_token' => $accessToken));
            
            if ($response->isError()) {
                $parsedErrors = (array) $this->parseResponseJson($response->getBody());
                $this->_setError($parsedErrors['meta']['errorDetail']);
                return false;
            } elseif ($response->isSuccessful()) {
                $parsedResponse = (array) $this->parseResponseJson($response->getBody());
                return isset($parsedResponse['response']['user']) ? $parsedResponse['response']['user'] : false;
            }
        }
        return false;
    }
    
}