<?php

/**  
 * @see SAuth_Adapter_Abstract 
 */
require_once 'Abstract.php';

/** require_once 'SAuth/Adapter/Abstract.php'; **/

/**
 * @see Zend_Auth_Adapter_Interface
 */
require_once 'Zend/Auth/Adapter/Interface.php';

/**
 * Authentication with vkontakte
 * 
 * http://vkontakte.ru/developers.php?oid=-1&p=Авторизация_сайтов
 */
class SAuth_Adapter_Vkontakte extends SAuth_Adapter_Abstract implements Zend_Auth_Adapter_Interface {
    
    /**
     * @var array Configuration array
     */
    protected $_config = array(
        'consumerId'            => '',
        'consumerSecret'        => '',
        'callbackUrl'           => '',
        'userAuthorizationUrl'  => 'http://api.vkontakte.ru/oauth/authorize',
        'accessTokenUrl'        => 'https://api.vkontakte.ru/oauth/access_token',
        'requestDatarUrl'       => 'https://graph.facebook.com/me',
        'responseType'          => 'code',
        'scope'                 => array(),
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
        
        if (isset($_GET['code']) && !empty($_GET['code'])) {
                
            $accessConfig = array(
                'client_id'     => $clientId,
                'client_secret' => $clientSecret,
                'code'          => trim($_GET['code']),
            );
            
            $response = $this->httpRequest('GET', $accessTokenUrl, $accessConfig);
            
            if ($response->isError()) {
                //vkontakte return 400 http code on error
                switch  ($response->getStatus()) {
                    case '400':
                        $parsedErrors = $this->parseResponseJson($response->getBody());
                        $error = $parsedErrors['error']['message'];
                        break;
                    default:
                        $error = 'Vkontakte Oauth service unavailable';
                        break;
                }
				
                return new Zend_Auth_Result(Zend_Auth_Result::FAILURE, false, array($error));
                
            } elseif ($response->isSuccessful()) {

                $parsedResponse = $this->parseResponseJson($response->getBody());

                /*
				Дополнительные поля, список с обозначениями тут: 
				http://vkontakte.ru/developers.php?oid=-1&p=Описание_полей_параметра_fields
				*/
				
				$userConfig = array(
                'uid'     => $parsedResponse['user_id'],
                'fields' => 'photo_rec,screen_name', 
                'access_token'  => $parsedResponse['access_token'],
				);
				
                $userRequest = $this->httpRequest('GET', 'https://api.vkontakte.ru/method/getProfiles', $userConfig);
				$userParameters = $this->parseResponseJson($userRequest->getBody());
				
                $identity = $this->_prepareIdentity(array_merge($parsedResponse, $userParameters['response']['0']));
                
                return new Zend_Auth_Result(Zend_Auth_Result::SUCCESS, $identity);
                
            }
        } elseif (!isset($_GET['error'])) {
            
            $authorizationConfig = array(
                'client_id'     => $clientId, 
                'redirect_uri'  => $redirectUrl.'/index/auth/by/vkontakte',
                'scope'  => 'audio',
                'response_type' => 'code',
            );
            
            $url = 'http://api.vkontakte.ru/oauth/authorize?';
            $url .= http_build_query($authorizationConfig, null, '&');
            header('Location: ' . $url);
            exit(1);
            
        } else {
            
            return new Zend_Auth_Result(Zend_Auth_Result::FAILURE, false, array($_GET['error']));
            
        }
    }
    
}