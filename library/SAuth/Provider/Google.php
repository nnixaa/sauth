<?php

/**  SAuth_Provider_Abstract */
require_once 'SAuth/Provider/Abstract.php';

/**  SAuth_Provider_Interface */
require_once 'SAuth/Provider/Interface.php';

/**  SAuth_Provider_Google_Extension */
require_once 'SAuth/Provider/Google/Extension.php';

/**  SAuth_Provider_Google_Extension */
require_once 'Ak33m/OpenId/Consumer.php';

/**
 * Authorisation with google
 * http://code.google.com/apis/accounts/docs/OpenID.html
 */
class SAuth_Provider_Google extends SAuth_Provider_Abstract implements SAuth_Provider_Interface {

    /**
     * @var array Configuration array
     */
    protected $_config = array(
        'id' => 'https://www.google.com/accounts/o8/id',
        'callbackUrl' => '',
        'root' => '',
        'exchangeExtension' => array(),
    );
    
    /**
     * @var string Session key
     */
    protected $_sessionKey = 'SAUTH_GOOGLE';
    
    /**
     * Authorized user by google OpenId
     * @param array $config
     * @return true
     */
    public function auth(array $config = array()) {
        
        $config = $this->setConfig($config);
        if (empty($config['id'])) {
            
            require_once 'SAuth/Exception.php';
            throw new SAuth_Exception('Invalid google OpenId url.');
        }
        $consumer = new Ak33m_OpenId_Consumer();
        $googleExt = new SAuth_Provider_Google_Extension();
        
        if (is_array($config['exchangeExtension']) && !empty($config['exchangeExtension'])) {
            $googleExt->setParams($config['exchangeExtension']);
        }
        if (!isset($_GET['openid_mode']) || empty($_GET['openid_mode'])) {
            $consumer->login($config['id'], $config['callbackUrl'], $config['root'], $googleExt);
            if ($error = $consumer->getError()) {
                throw new SAuth_Exception($error);
            }
        } elseif (isset($_GET['openid_mode']) && $_GET['openid_mode'] == 'id_res') {
                
            if ($consumer->verify($_GET, $id, $googleExt)) {
                $this->_setTokenAccess($_GET['openid_identity']);
                $this->setUserParameters($_GET);
                return $this->isAuthorized();
            } else {
                $this->_setError('Google openId verification has been faild');
                return false;
            }
        }
        return false;
        
    }

    /**
     * Getting authentication identification
     * @return false|int User ID
     */
    public function getAuthId() {
        
        $id = $this->getUserParameters('openid_identity');
        return empty($id) ? false : $id;
    }
    
}