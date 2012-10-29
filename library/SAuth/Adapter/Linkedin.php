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
 * Authentication with linkedin
 * 
 * https://developer.linkedin.com/documents/authentication
 */
class SAuth_Adapter_Linkedin extends SAuth_Adapter_Abstract implements Zend_Auth_Adapter_Interface {
    
    /**
     * @var array Configuration array
     */
    protected $_config = array(
        'requestScheme'         => Zend_Oauth::REQUEST_SCHEME_HEADER,
        'consumerKey'           => '',
        'consumerSecret'        => '',
        'version'               => '1.0',
        'callbackUrl'           => '',
        'requestTokenUrl'       => 'https://api.linkedin.com/uas/oauth/requestToken',
        'scope'                 => array(),
        'userAuthorizationUrl'  => 'https://api.linkedin.com/uas/oauth/authenticate',
        'accessTokenUrl'        => 'https://api.linkedin.com/uas/oauth/accessToken',
        'requestDatarUrl'       => 'https://api.linkedin.com/v1/people/~',
        'userFields'            => array(),
    );
    
    /**
     * @var string Session key
     */
    protected $_sessionKey = 'SAUTH_LINKEDIN';
    
    /**
     * Authenticate user by Linkedin OAuth
     * @return Zend_Auth_Result
     */
    public function authenticate() {
        
        $config = $this->getConfig();
        
        if (empty($config['consumerKey']) || empty($config['consumerSecret']) || empty($config['userAuthorizationUrl']) 
            || empty($config['accessTokenUrl']) || empty($config['callbackUrl'])) {
                
            require_once 'Zend/Auth/Adapter/Exception.php';
            throw new Zend_Auth_Adapter_Exception('Linkedin auth configuration not specifed');
        }
        
        if (isset($config['scope']) && !empty($config['scope'])) {
            $scope = $config['scope'];
        }
        else
        {
            $scope = array();
        }
        
        $consumer = new Zend_Oauth_Consumer($config);
        $tokenRequest = $this->_getTokenRequest();
        
        if (!empty($tokenRequest) && !empty ($_GET)) {
            
            $accessToken = $consumer->getAccessToken($_GET, $tokenRequest);
            $response = $accessToken->getResponse();
            
            if ($response->isError()) {
                //TODO:change on custom
                $error = 'Linkedin Oauth service unavailable';
                return new Zend_Auth_Result(Zend_Auth_Result::FAILURE, false, array($error));
               
            } elseif ($response->isSuccessful()) {

                $parsedResponse = $this->parseResponseUrl($response->getBody());

                // making an additional call, to receive the user parameters
                $User = $this->requestUserParams($accessToken);
                
                $parsedResponse = array_merge($parsedResponse, $User);

                $this->_unsetTokenRequest();
                
                $identity = $this->_prepareIdentity($parsedResponse);
                
                return new Zend_Auth_Result(Zend_Auth_Result::SUCCESS, $identity);
            }
            
        } else {
            
            $tokenRequest = $consumer->getRequestToken(array('scope'=>implode(' ', $scope)));
            $this->_setTokenRequest($tokenRequest);
            $consumer->redirect();
        }
    }
    
    /**
     * Request user parameters using linkedin API
     * @return array User params
     */
    public function requestUserParams($accessToken) {
        
        $requestDataUrl = $this->getConfig('requestDatarUrl');

        if ($accessToken && !empty($requestDataUrl)) {
            
            $options = array('consumerKey'     => $this->getConfig('consumerKey'),
                             'consumerSecret'  => $this->getConfig('consumerSecret'));
                
            // retreiving the special OAuth http client
            $client = $accessToken->getHttpClient($options);

            $userFields = $this->getConfig('userFields');
            
            if(is_array($userFields) && !empty($userFields))
            {
                
            }
            else
            {
                 $userFields = false;
            }
            
            $client->setUri($requestDataUrl.($userFields?':('.implode(',', $userFields).')':''));
            $client->setMethod(Zend_Http_Client::GET);
            $response = $client->request();
            $content = $response->getBody();
            
            if ($response->isError()) {
                // TODO: maybe will better return an error?
                // $parsedErrors = (array) $this->parseResponseJson($response->getBody());
                return false;
            } elseif ($response->isSuccessful()) {
                
                // xml output is used, because there are problems with the ZF OAuth library (probably), when using suffix ?format=json
                $xmlContent = simplexml_load_string($content);
                
                return $this->parseResponseJson(Zend_Json::encode($xmlContent));
            }
        }
        return false;
    }
    
}