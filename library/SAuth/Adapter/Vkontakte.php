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
 * http://vkontakte.ru/developers.php?o=-1&p=Open+API
 */
class SAuth_Adapter_Vkontakte extends SAuth_Adapter_Abstract implements Zend_Auth_Adapter_Interface {
    
    /**
     * @var array Configuration array
     */
    protected $_config = array(
        'consumerId'        => '',
        'consumerSecret'    => '',
        'callbackUrl'       => '',
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
        
        $apiId      = $config['consumerId'];
        $apiSecret  = $config['consumerSecret'];
        
        if (empty($apiId) || empty($apiSecret)) {
            
            require_once 'Zend/Auth/Adapter/Exception.php';
            throw new Zend_Auth_Adapter_Exception('Vkontakte auth configuration not specifed');
        }

        $appCookie = isset($_COOKIE['vk_app_' . $apiId]) ? $this->parseResponseUrl($_COOKIE['vk_app_' . $apiId]) : null;
        $vkUserCookie = isset($_COOKIE['vk_user_info_' . $apiId]) ? $this->parseResponseUrl($_COOKIE['vk_user_info_' . $apiId]) : null;
        
        if (!empty($appCookie)) {
            //create sign
            $sign = 'expire=' . $appCookie['expire'] . 'mid=' . $appCookie['mid'] . 'secret=' . $appCookie['secret']
                . 'sid=' . $appCookie['sid'];
            $sign =  md5($sign . $apiSecret);
            
            if ($appCookie['sig'] == $sign) {
                
                //unset vk info cookie
                setcookie('vk_user_info_' . $apiId, '', time() - 1000, '/');
                
                $identity = $this->_prepareIdentity(array_merge($appCookie, $vkUserCookie));
                
                return new Zend_Auth_Result(Zend_Auth_Result::SUCCESS, $identity);
            }
        }

        $error = 'Vkontakte auth failed';
        return new Zend_Auth_Result(Zend_Auth_Result::FAILURE, false, array($error));
    }
    
}