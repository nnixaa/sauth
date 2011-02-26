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
 * Authentication with mail.ru
 * 
 * http://api.mail.ru/docs/guides/oauth/sites/
 * http://api.mail.ru/sites/my/
 * http://api.mail.ru/docs/guides/restapi/
 */
class SAuth_Adapter_Mailru extends SAuth_Adapter_Abstract implements Zend_Auth_Adapter_Interface {
    
    /**
     * @var array Configuration array
     */
    protected $_config = array(
        'consumerId' => '',
        'privateKey' => '',
        'consumerSecret' => '',
        'callbackUrl' => '',
        'userAuthorizationUrl' => 'https://connect.mail.ru/oauth/authorize',
        'accessTokenUrl' => 'https://connect.mail.ru/oauth/token',
        'requestDatarUrl' => 'http://www.appsmail.ru/platform/api',
        'responseType' => 'code',
    );
    
    /**
     * @var string Session key
     */
    protected $_sessionKey = 'SAUTH_MAILRU';
    
    /**
     * Authenticate user by mail.ru OAuth 2.0
     * @return true
     */
    public function authenticate() {
        
        $config = $this->getConfig();
        
        $authorizationUrl = $config['userAuthorizationUrl'];
        $accessTokenUrl = $config['accessTokenUrl'];
        $clientId = $config['consumerId'];
        $clientSecret = $config['consumerSecret'];
        $privateKey = $config['privateKey'];
        $redirectUrl = $config['callbackUrl'];
        $responseType = $config['responseType'];
        
        if (empty($authorizationUrl) || empty($clientId) || empty($clientSecret) || empty($redirectUrl) 
            || empty($accessTokenUrl) || empty($privateKey)) {
                
            require_once 'SAuth/Exception.php';    
            throw new SAuth_Exception('Mail.ru auth configuration not specifed.');
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
                //mail.ru return 400 http code on error
                switch  ($response->getStatus()) {
                    case '400':
                        $parsedErrors = $this->parseResponseJson($response->getBody());
                        $error = $parsedErrors['error'];
                        break;
                    default:
                        $error = 'Mail.ru Oauth service unavailable';
                        break;
                }
                
                return new Zend_Auth_Result(Zend_Auth_Result::FAILURE, false, array($error));
                
            } elseif ($response->isSuccessful()) {
                
                $parsedResponse = $this->parseResponseJson($response->getBody());

                $userParameters = $this->requestUserParams($parsedResponse['access_token']);
                
                return new Zend_Auth_Result(Zend_Auth_Result::SUCCESS, $userParameters);
                
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
        
        $id = (int) $this->getUserParameters('uid');
        return $id > 0 ? $id : false;
    }
    
    /**
     * Request user params on mail.ru using REST API
     * http://api.mail.ru/docs/reference/rest/users-getinfo/
     * FIXME: Working only after auth process, because don't consider expire time
     * @return array User params
     */
    public function requestUserParams($accessToken) {
        
        $restUrl = $this->getConfig('requestDatarUrl');
        $config = $this->getConfig();
        
        if ($accessToken && !empty($restUrl)) {

            $requestParametrs = array(
                'app_id' => $config['consumerId'],
                'method' => 'users.getInfo',
                'secure' => 1,
                'session_key' => $accessToken,
            );
            $sig = $this->getSign($requestParametrs, $accessToken);
            $requestParametrs['sig'] = $sig;
            
            $response = $this->httpRequest('POST', $restUrl, $requestParametrs);
            
            if ($response->isError()) {
                $parsedErrors = (array) $this->parseResponseJson($response->getBody());
                $this->_setError($parsedErrors['error']['error_msg']);
                return false;
            } elseif ($response->isSuccessful()) {
                $parsedResponse = (array) $this->parseResponseJson($response->getBody());
                return isset($parsedResponse[0]) ? $parsedResponse[0] : false;
            }
        }
        return false;
    }
    
    /**
     * Return mail.ru sign
     * @param array $requestParams Request parameters
     * @return string Signature
     */
    public function getSign(array $requestParams, $accessToken) {
        
        $config = $this->getConfig();

        $consumerSecret = $config['consumerSecret'];
        ksort($requestParams);

        $params = '';
        foreach ($requestParams as $key => $value) {
            $params .= $key . '=' . $value;
        }
        return md5($params . $consumerSecret);
    }    
}