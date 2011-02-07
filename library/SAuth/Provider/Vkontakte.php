<?php

/**
 * Authorisation with vkontakte
 * http://vkontakte.ru/developers.php?o=-1&p=Open+API
 */
class SAuth_Provider_Vkontakte extends SAuth_Provider_Abstract{
    
    /**
     * @var array Configuration array
     */
    protected $_config = array(
        'apiId' => '',
        'apiSecret' => '',
        'redirectUrl' => '',
    );
    
    /**
     * @var string Session key
     */
    protected $_sessionKey = 'SAUTH_VKONTAKTE';
    
    /**
     * Authorized user
     * @param array $config
     * @return true
     */
    public function auth(array $config = array()) {
        
        if ($this->isAuthorized()) {
            return true;
        }
        
        $config = $this->setConfig($config);
        
        $apiId = $config['apiId'];
        $apiSecret = $config['apiSecret'];
        
        if (empty($apiId) || empty($apiId)) {
            throw new SAuth_Exception('Vkontakte auth configuration not specifed.');
        }
        $appCookie = isset($_COOKIE['vk_app_' . $apiId]) ? $this->_parseResponse($_COOKIE['vk_app_' . $apiId]) : null;
        $vkUserCookie = isset($_COOKIE['vk_user_info_' . $apiId]) ? $this->_parseResponse($_COOKIE['vk_user_info_' . $apiId]) : null;
        if (!empty($appCookie)) {
            //create sign
            $sign = 'expire=' . $appCookie['expire'] . 'mid=' . $appCookie['mid'] . 'secret=' . $appCookie['secret']
                . 'sid=' . $appCookie['sid'];
            $sign =  md5($sign . $apiSecret);
            if ($appCookie['sig'] == $sign) {
                $this->_setTokenAccess($sign);
                $this->setUserParameters((array) $appCookie);
                $this->setUserParameters((array) $vkUserCookie);
                //unset vk info cookie
                setcookie('vk_user_info_' . $apiId, '', time()-1000, '/');
                
                if (!empty($config['redirectUrl'])) {
                    header('Location:' . $config['redirectUrl']);
                    exit(1);
                }
                return $this->isAuthorized();
            }
        }
        return false;
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