<?php

/**
 * Authorisation with facebook
 * http://developers.facebook.com/docs/authentication
 */
class SAuth_Provider_Facebook extends SAuth_Provider_Abstract implements SAuth_Provider_Interface {
    
    /**
     * @var array Configuration array
     */
    protected $_config = array(
        'consumerKey' => '',
        'consumerSecret' => '',
        'clientId' => '',
        'redirectUri' => '',
        'userAuthorizationUrl' => 'http://www.facebook.com/dialog/oauth',
        'accessTokenUrl' => 'https://graph.facebook.com/oauth/access_token',
        'graphUrl' => 'https://graph.facebook.com',
        'scope' => null,
    );
    
    /**
     * @var string Session key
     */
    protected $_sessionKey = 'SAUTH_FACEBOOK';
    
    /**
     * Authorized user by facebook OAuth 2.0
     * @param array $config
     * @return true
     */
    public function auth(array $config = array()) {
        
        $config = $this->setConfig($config);
        
        $authorizationUrl = $config['userAuthorizationUrl'];
        $accessTokenUrl = $config['accessTokenUrl'];
        $clientId = $config['clientId'];
        $clientSecret = $config['consumerSecret'];
        $redirectUrl = $config['redirectUri'];
        
        if (empty($authorizationUrl) || empty($clientId) || empty($clientSecret) || empty($redirectUrl) || empty($accessTokenUrl)) {
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
                'scope' => implode($scope, ','),
            );
            
            $client = new Zend_Http_Client();
            $client->setUri($accessTokenUrl);
            $client->setParameterPost($accessConfig);
            $response = $client->request(Zend_Http_Client::POST);
            
            if ($response->isError()) {
                //facebook return 400 http code on error
                switch  ($response->getStatus()) {
                    case '400':
                        $parsedErrors = Zend_Json::decode($response->getBody());
                        $error = $parsedErrors['error']['message'];
                        break;
                    default:
                        $error = 'OAuth service unavailable.';
                        break;
                }
                return false;
            } elseif ($response->isSuccessful()) {
                
                $parsedResponse = $this->_parseResponse($response->getBody());
                $this->_setTokenAccess($parsedResponse['access_token']);
                //try to get user data
                if ($userParameters = $this->requestUserParams()) {
                    $this->setUserParameters($userParameters);
                }
                return $this->isAuthorized();
            }
        } else {
            
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
        
        $graphUrl = $this->getConfig('graphUrl');
        $accessToken = $this->_getTokenAccess();

        if ($accessToken && !empty($graphUrl)) {
            $client = new Zend_Http_Client();
            $url = $graphUrl . '/me';
            $client->setUri($url);
            $client->setParameterGET(array('access_token' => $accessToken));
            $response = $client->request(Zend_Http_Client::GET);
            if ($response->isError()) {
                $error = 'Request user parameters failed.';
                return false;
            } elseif ($response->isSuccessful()) {
                return Zend_Json::decode($response->getBody());
            }
        }
        return false;
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