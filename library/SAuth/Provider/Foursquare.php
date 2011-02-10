<?php

/**  SAuth_Provider_Abstract */
require_once 'SAuth/Provider/Abstract.php';

/**  SAuth_Provider_Interface */
require_once 'SAuth/Provider/Interface.php';

/**  Zend_Http_Client */
require_once 'Zend/Http/Client.php';


/**
 * Authentication with foursquare
 * 
 * http://developer.foursquare.com/docs/oauth.html
 */
class SAuth_Provider_Foursquare extends SAuth_Provider_Abstract implements SAuth_Provider_Interface {
    
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
        'requestDatarUrl' => 'https://api.foursquare.com/v2',
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
        
        if ($this->isAuthorized()) {
            $this->clearAuth();
        }
        
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
            
            $client = new Zend_Http_Client();
            $client->setUri($accessTokenUrl);
            $client->setParameterPost($accessConfig);
            $response = $client->request(Zend_Http_Client::POST);
            
            if ($response->isError()) {
                //foursquare return 400 http code on error
                switch  ($response->getStatus()) {
                    case '400':
                        $parsedErrors = $this->parseResponseJson($response->getBody());
                        $this->_setError($parsedErrors['error']);
                        break;
                    default:
                        $this->_setError('Foursquare Oauth service unavailable');
                        break;
                }

                return false;
            } elseif ($response->isSuccessful()) {
                
                $parsedResponse = $this->parseResponseJson($response->getBody());
                $this->_setTokenAccess($parsedResponse['access_token']);
                //try to get user data
                if ($userParameters = $this->requestUserParams()) {
                    $this->setUserParameters($userParameters);
                }
                return $this->isAuthorized();
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
            $this->_setError($_GET['error']);
            return false;
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
    public function requestUserParams() {
        
        if (!$this->isAuthorized()) {
            return false;
        }
        
        $apiUrl = $this->getConfig('requestDatarUrl');
        $accessToken = $this->_getTokenAccess();

        if ($accessToken && !empty($apiUrl)) {
            $client = new Zend_Http_Client();
            $url = $apiUrl . '/users/self';
            $client->setUri($url);
            $client->setParameterGET(array('oauth_token' => $accessToken));
            $response = $client->request(Zend_Http_Client::GET);
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