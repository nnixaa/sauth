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
 * Authentication with Flickr
 * 
 * http://www.flickr.com/services/api/auth.howto.web.html
 */
class SAuth_Adapter_Flickr extends SAuth_Adapter_Abstract implements Zend_Auth_Adapter_Interface {
    
    /**
     * Permission
     */
    const PERMS_READ    = 'read';
    const PERMS_WRITE   = 'write';
    const PERMS_DELETE  = 'delete';
    
    /**
     * Response state
     */
    const RESPONSE_FAIL = 'fail';
    const RESPONSE_OK   = 'ok';
    
    /**
     * @var array Configuration array
     */
    protected $_config = array(
        'consumerSecret'        => '',
        'consumerKey'           => '',
        'userAuthorizationUrl'  => 'http://flickr.com/services/auth/',
        //TODO: maybe apiUrl?
        'requestDataUrl'        => 'http://api.flickr.com/services/rest/',
        'permission'            => '',
    );
    
    /**
     * @var string Session key
     */
    protected $_sessionKey = 'SAUTH_FLICKR';
    
    /**
     * Authenticate user by flickr
     * @return Zend_Auth_Result
     */
    public function authenticate() {
        
        $config = $this->getConfig();
        
        $authorizationUrl   = $config['userAuthorizationUrl'];
        $clientKey          = $config['consumerKey'];
        $clientSecret       = $config['consumerSecret'];
        $permsissions       = $config['permission'];
        $apiUrl             = $config['requestDataUrl'];
        
        //TODO: chage this check
        if (empty($authorizationUrl) || empty($clientKey) || empty($clientSecret) || empty($permsissions)
            || empty($apiUrl)) {
                
            require_once 'Zend/Auth/Adapter/Exception.php';
            throw new Zend_Auth_Adapter_Exception('Flickr auth configuration not specifed');
        }
            
        if (isset($_GET['frob']) && !empty($_GET['frob'])) {
            
            $authTokenConfig = array(
                'method'    => 'flickr.auth.getToken',
                'api_key'   => $clientKey,
                'frob'      => trim($_GET['frob']),
                'format'    => 'json',
            );
            
            
            $authTokenConfig['api_sig'] = $this->createSign($authTokenConfig);
            
            $response = $this->httpRequest('GET', $apiUrl, $authTokenConfig);
            
            if ($response->isSuccessful()) {
                
                if (preg_match('/jsonFlickrApi\((.*)\)/', $response->getBody(), $result)) {
                    
                    $parsedResponse = (array) $this->parseResponseJson($result[1]);
                
                    if (isset($parsedResponse['stat']) && self::RESPONSE_OK == $parsedResponse['stat']) {
                    
                        $identity = $this->_prepareIdentity($parsedResponse['auth']);
                
                        return new Zend_Auth_Result(Zend_Auth_Result::SUCCESS, $identity);
                    
                    } elseif (isset($parsedResponse['stat']) && self::RESPONSE_FAIL == $parsedResponse['stat']) {
                        
                        $error = $parsedResponse['message'];
                    }
                    
                } else {
                    
                    $error = 'Invalid Flickr response';
                }
                
            } elseif ($response->isError()) {

                $error = 'Flickr service service unavailable';
            }
            
            return new Zend_Auth_Result(Zend_Auth_Result::FAILURE, false, array($error));
            
        } else {
            
            $authorizationConfig = array(
                'api_key'   => $clientKey,
                'perms'     => $permsissions,
            );
            
            $authorizationConfig['api_sig'] = $this->createSign($authorizationConfig);
            
            $url = $authorizationUrl . '?';
            $url .= http_build_query($authorizationConfig, null, '&');
            header('Location: ' . $url);
            exit(1);
        }

    }
    
    /**
     * Request user parameters on flickr
     * @return array User params
     */
    public function requestUserParams($accessToken) {

    }
    
    /**
     * Returns flickr sign  
     * @param array $requestParams Request parameters
     * @return string Signature
     */
    public function createSign(array $requestParams) {
        
        $config = $this->getConfig();

        $consumerSecret = $config['consumerSecret'];
        ksort($requestParams);

        $params = '';
        foreach ($requestParams as $key => $value) {
            $params .= $key . $value;
        }
        return md5($consumerSecret . $params);
    } 
    
}