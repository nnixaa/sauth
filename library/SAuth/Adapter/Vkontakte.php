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
 * Authentication with vkontakte
 * 
 * http://vkontakte.ru/developers.php?o=-1&p=Авторизация_сайтов
 */
class SAuth_Adapter_Vkontakte extends SAuth_Adapter_Abstract implements Zend_Auth_Adapter_Interface {
    
	/**
	 * 
	 */
	const RESPONSE_TYPE_CODE = 'code';

	/**
     * @var array Configuration array
     */
    protected $_config = array(
        'consumerId'			=> '',
        'consumerSecret'		=> '',
        'callbackUrl'			=> '',
        'userAuthorizationUrl'	=> 'http://oauth.vkontakte.ru/authorize',
        'accessTokenUrl'		=> 'https://oauth.vkontakte.ru/access_token',
        'requestDataUrl'		=> 'https://api.vkontakte.ru/method/users.get',
        'responseType'			=> self::RESPONSE_TYPE_CODE,
        'scope'					=> array('notify'),
		
    );
    
	/**
     * @var string Session key
     */
    protected $_sessionKey = 'SAUTH_VKONTAKTE';
    
    /**
     * Authenticate user
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
            throw new Zend_Auth_Adapter_Exception('Vkontakte auth configuration not specifed');
        }

        if (isset($config['scope']) && !empty($config['scope'])) {
            $scope = $config['scope'];
        }
        
		if (isset($_GET['code']) && !empty($_GET['code'])) {
            	
            $accessConfig = array(
                'client_id'     => $clientId,
                'client_secret' => $clientSecret,
				'code'			=> $_GET['code'] 
            );
		
			$response = $this->httpRequest('GET', $accessTokenUrl, $accessConfig);

			if ( $response->isError() ) {

				switch  ($response->getStatus()) {
                    case '400':
                        $parsedErrors = $this->parseResponseJson($response->getBody());
                        $error = $parsedErrors['error_description'];
                        break;
                    default:
                        $error = 'VK Oauth service unavailable';
                        break;
                }

				return new Zend_Auth_Result(Zend_Auth_Result::FAILURE, false, array($error));
                
            } elseif ($response->isSuccessful()) {
                
                $parsedResponse = $this->parseResponseJson($response->getBody());

                $userParameters = $this->requestUserParams($parsedResponse['access_token'], $parsedResponse['user_id']);
				if ( !is_array($userParameters) ) {
					return new Zend_Auth_Result(Zend_Auth_Result::FAILURE, false, array("Can't retrieve user data"));
				}
				
				$identity = $this->_prepareIdentity(array_merge($parsedResponse, $userParameters));
                
                return new Zend_Auth_Result(Zend_Auth_Result::SUCCESS, $identity);
			}

		} else {
            
			$authorizationConfig = array(
                'client_id'     => $clientId, 
                'redirect_uri'  => $redirectUrl,
                'response_type' => $responseType,
            );
			
			if (isset($scope)) {
                $authorizationConfig['scope'] = implode($scope, ',');
            }
			
			$url = $authorizationUrl . '?';
            $url .= http_build_query($authorizationConfig, null, '&');
            header('Location: ' . $url);
            exit(1);
		}

		return new Zend_Auth_Result(Zend_Auth_Result::FAILURE, false, array($_GET['error']));
    }

    /**
     * Request user parameters
     * @return array User params
     */
    public function requestUserParams( $accessToken, $userId ) {
        
        $userDataUrl = $this->getConfig('requestDataUrl');

        if ( $accessToken && !empty($userDataUrl) ) {
            
			$requestParams = array(
					'access_token'	=> $accessToken,
					'uids'			=> $userId,
			);
			
			$userFields = $this->getConfig('userFields');
			
			if ( is_array( $userFields ) && count( $userFields ) > 0 ) {
				$requestParams['fields'] = $userFields;
			}
			
            $response = $this->httpRequest('GET', $userDataUrl, $requestParams );
            $body = $this->parseResponseJson($response->getBody());
			
			if ($response->isError()) {
                return false;
            } elseif ($response->isSuccessful() && array_key_exists('response', $body) && is_array( $body['response'] ) ) {
                return $body['response'][0];
            }
        }
		
        return false;
    }	
}