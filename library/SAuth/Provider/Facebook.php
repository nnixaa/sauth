<?php

/**  SAuth_Provider_Abstract */
require_once 'SAuth/Provider/Abstract.php';

/**  SAuth_Provider_Interface */
require_once 'SAuth/Provider/Interface.php';

/**  Zend_Http_Client */
require_once 'Zend/Http/Client.php';

/**
 * Authentication with facebook
 * 
 * http://developers.facebook.com/docs/authentication
 */
class SAuth_Provider_Facebook extends SAuth_Provider_Abstract implements SAuth_Provider_Interface {
    
    /**
     * @var array Configuration array
     */
    protected $_config = array(
        'consumerId' => '',
        'consumerKey' => '',
        'consumerSecret' => '',
        'callbackUrl' => '',
        'userAuthorizationUrl' => 'http://www.facebook.com/dialog/oauth',
        'accessTokenUrl' => 'https://graph.facebook.com/oauth/access_token',
        'requestDatarUrl' => 'https://graph.facebook.com/me',
        'scope' => array(),
    );
    
    /**
     * @var string Session key
     */
    protected $_sessionKey = 'SAUTH_FACEBOOK';
    
    /**
     * Authenticate user by facebook OAuth 2.0
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
        
        if (empty($authorizationUrl) || empty($clientId) || empty($clientSecret) || empty($redirectUrl) 
            || empty($accessTokenUrl)) {
                
            require_once 'SAuth/Exception.php';    
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
            );
            if (isset($scope)) {
                $accessConfig['scope'] = implode($scope, ',');
            }
            $client = new Zend_Http_Client();
            $client->setUri($accessTokenUrl);
            $client->setParameterPost($accessConfig);
            $response = $client->request(Zend_Http_Client::POST);
            
            if ($response->isError()) {
                //facebook return 400 http code on error
                switch  ($response->getStatus()) {
                    case '400':
                        $parsedErrors = $this->parseResponseJson($response->getBody());
                        $this->_setError($parsedErrors['error']['message']);
                        break;
                    default:
                        $this->_setError('Facebook Oauth service unavailable');
                        break;
                }

                return false;
            } elseif ($response->isSuccessful()) {
                
                $parsedResponse = $this->parseResponseUrl($response->getBody());
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
            );
            if (isset($scope)) {
                $authorizationConfig['scope'] = implode($scope, ',');
            }
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
     * Request user parameters on facebook using Graph API
     * @return array User params
     */
    public function requestUserParams() {
        
        if (!$this->isAuthorized()) {
            return false;
        }
        
        $graphUrl = $this->getConfig('requestDatarUrl');
        $accessToken = $this->_getTokenAccess();

        if ($accessToken && !empty($graphUrl)) {
            $client = new Zend_Http_Client();
            $client->setUri($graphUrl);
            $client->setParameterGet(array('access_token' => $accessToken));
            $response = $client->request(Zend_Http_Client::GET);
            if ($response->isError()) {
                $parsedErrors = (array) $this->parseResponseJson($response->getBody());
                $this->_setError($parsedErrors['error']['message']);
                return false;
            } elseif ($response->isSuccessful()) {
                return $this->parseResponseJson($response->getBody());
            }
        }
        return false;
    }
    
}