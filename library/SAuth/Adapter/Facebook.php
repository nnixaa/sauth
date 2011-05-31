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
 * Authentication with facebook
 * 
 * http://developers.facebook.com/docs/authentication
 */
class SAuth_Adapter_Facebook extends SAuth_Adapter_Abstract implements Zend_Auth_Adapter_Interface {
    
    /**
     * Display modes
     * http://developers.facebook.com/docs/reference/dialogs/#display
     */
    const DISPLAY_PAGE      = 'page';
    const DISPLAY_POPUP     = 'popup';
    const DISPLAY_IFRAME    = 'iframe';
    
    /**
     * Response types
     */
    const RESPONSE_TYPE_CODE        = 'code';
    const RESPONSE_TYPE_TOKEN       = 'token';
    const RESPONSE_TYPE_CODE_TOKEN  = 'code_and_token';
    
    /**
     * @var array Configuration array
     */
    protected $_config = array(
        'consumerId'            => '',
        'consumerSecret'        => '',
        'callbackUrl'           => '',
        'userAuthorizationUrl'  => 'http://www.facebook.com/dialog/oauth',
        'accessTokenUrl'        => 'https://graph.facebook.com/oauth/access_token',
        'requestDatarUrl'       => 'https://graph.facebook.com/me',
        'responseType'          => self::RESPONSE_TYPE_CODE,
        'display'               => self::DISPLAY_PAGE,
        'scope'                 => array(),
    );
    
    /**
     * @var string Session key
     */
    protected $_sessionKey = 'SAUTH_FACEBOOK';
    
    /**
     * Authenticate user by facebook OAuth 2.0
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
        
        if (empty($authorizationUrl) || empty($clientId) || empty($clientSecret) || empty($redirectUrl) 
            || empty($accessTokenUrl)) {
                
            require_once 'Zend/Auth/Adapter/Exception.php';
            throw new Zend_Auth_Adapter_Exception('Facebook auth configuration not specifed');
        }

        if (isset($config['scope']) && !empty($config['scope'])) {
            $scope = $config['scope'];
        }
        
        if (isset($_GET['code']) && !empty($_GET['code'])) {
            	
            $accessConfig = array(
                'client_id'     => $clientId,
                'redirect_uri'  => $redirectUrl,
                'client_secret' => $clientSecret,
                'code'          => trim($_GET['code']),
            );
            if (isset($scope)) {
                $accessConfig['scope'] = implode($scope, ',');
            }
            
            $response = $this->httpRequest('POST', $accessTokenUrl, $accessConfig);
            
            if ($response->isError()) {
                //facebook return 400 http code on error
                switch  ($response->getStatus()) {
                    case '400':
                        $parsedErrors = $this->parseResponseJson($response->getBody());
                        $error = $parsedErrors['error']['message'];
                        break;
                    default:
                        $error = 'Facebook Oauth service unavailable';
                        break;
                }

                return new Zend_Auth_Result(Zend_Auth_Result::FAILURE, false, array($error));
                
            } elseif ($response->isSuccessful()) {
                
                $parsedResponse = $this->parseResponseUrl($response->getBody());

                //try to get user data
                $userParameters = (array) $this->requestUserParams($parsedResponse['access_token']);
                $identity = $this->_prepareIdentity(array_merge($parsedResponse, $userParameters));
                
                return new Zend_Auth_Result(Zend_Auth_Result::SUCCESS, $identity);
                
            }
        } elseif (!isset($_GET['error'])) {
            
            $authorizationConfig = array(
                'client_id'     => $clientId, 
                'redirect_uri'  => $redirectUrl,
                'display'       => $config['display'],
                'response_type' => $responseType,
            );
            
            if (isset($scope)) {
                $authorizationConfig['scope'] = implode($scope, ',');
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
     * Request user parameters on facebook using Graph API
     * @return array User params
     */
    public function requestUserParams($accessToken) {
        
        $graphUrl = $this->getConfig('requestDatarUrl');

        if ($accessToken && !empty($graphUrl)) {
            
            $response = $this->httpRequest('GET', $graphUrl, array('access_token' => $accessToken));
            
            if ($response->isError()) {
                // TODO: maybe will better return an error?
                // $parsedErrors = (array) $this->parseResponseJson($response->getBody());
                return false;
            } elseif ($response->isSuccessful()) {
                return $this->parseResponseJson($response->getBody());
            }
        }
        return false;
    }
    
}