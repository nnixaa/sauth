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
 * @see SAuth_Adapter_Google_Extension 
 */
require_once 'SAuth/Adapter/Google/Extension.php';

/**  
 * @see Ak33m_OpenId_Consumer
 */
require_once 'Ak33m/OpenId/Consumer.php';

/**
 * Authentication with google
 * 
 * http://code.google.com/apis/accounts/docs/OpenID.html
 */
class SAuth_Adapter_Google extends SAuth_Adapter_Abstract implements Zend_Auth_Adapter_Interface {

    /**
     * @var array Configuration array
     */
    protected $_config = array(
        'id'                => 'https://www.google.com/accounts/o8/id',
        'callbackUrl'       => '',
        'root'              => '',
        'exchangeExtension' => array(),
    );
    
    /**
     * @var string Session key
     */
    protected $_sessionKey = 'SAUTH_GOOGLE';
    
    /**
     * Authenticate user by google OpenId
     * @return Zend_Auth_Result
     */
    public function authenticate() {
        
        $config = $this->getConfig();
        
        if (empty($config['id'])) {
            
            require_once 'Zend/Auth/Adapter/Exception.php';
            throw new Zend_Auth_Adapter_Exception('Invalid google OpenId url');
        }
        
        $consumer = new Ak33m_OpenId_Consumer();
        $googleExt = new SAuth_Provider_Google_Extension();
        
        if (is_array($config['exchangeExtension']) && !empty($config['exchangeExtension'])) {
            
            $googleExt->setParams($config['exchangeExtension']);
        }

        if (!isset($_GET['openid_mode']) || empty($_GET['openid_mode'])) {

            $consumer->login($config['id'], $config['callbackUrl'], $config['root'], $googleExt);
            if ($error = $consumer->getError()) {

                return new Zend_Auth_Result(Zend_Auth_Result::FAILURE, false, array($error));

            }
        } elseif (isset($_GET['openid_mode']) && $_GET['openid_mode'] == 'id_res') {
                
            if ($consumer->verify($_GET, $id, $googleExt)) {
                
                $identity = $this->_prepareIdentity($_GET);
                
                return new Zend_Auth_Result(Zend_Auth_Result::SUCCESS, $identity);
            }
        }
        
        $error = 'Google openId verification has been faild';
        return new Zend_Auth_Result(Zend_Auth_Result::FAILURE, false, array($error));
        
    }
    
}