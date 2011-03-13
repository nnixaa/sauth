<?php

class Bootstrap extends Zend_Application_Bootstrap_Bootstrap
{
    
    protected function _initApp() {
        $autoloader = Zend_Loader_Autoloader::getInstance();
        $autoloader->registerNamespace('SAuth_');
    }

    /**
     * TODO: You should specify your own configuration
     */
    protected function _initSauth() {
        
        /**
         * @see application.ini
         */
        $siteDir = $this->getOption('siteDir');
        $siteUrl = $this->getOption('siteUrl');
        
        $sauthConf['google'] = array(
            'id' => 'https://www.google.com/accounts/o8/id',
            'callbackUrl' => $siteUrl . $siteDir . '/index/auth/by/google',
            'exchangeExtension' => array(
                'openid.ns.ax' => 'http://openid.net/srv/ax/1.0',
                'openid.ax.mode' => 'fetch_request',
                'openid.ax.type.email' => 'http://axschema.org/contact/email',
                'openid.ax.required' => 'email',
            ),
        );
        
        $sauthConf['twitter'] = array(
            'consumerKey' => '',
            'consumerSecret' => '',
            'callbackUrl' => $siteUrl . $siteDir . '/index/auth/by/twitter',
        );
          
        $sauthConf['facebook'] = array(
            'consumerId' => '',
            'consumerSecret' => '',
            'callbackUrl' => $siteUrl . $siteDir . '/index/auth/by/facebook',
            'display' => SAuth_Adapter_Facebook::DISPLAY_POPUP,
            'scope' => array(
                 'user_about_me', 'email',
            ),
        );
        
        $sauthConf['vkontakte'] = array(
            'consumerId' => '',
            'consumerSecret' => '',
            'userAuthorizationUrl' => $siteUrl . $siteDir . '/index/auth/by/vkontakte',
            'callbackUrl' => $siteUrl . $siteDir,
        );
        
        $sauthConf['mailru'] = array(
            'consumerId' => '',
            'privateKey' => '',
            'consumerSecret' => '',
            'callbackUrl' => $siteUrl . $siteDir . '/index/auth/by/mailru',
        );
        
        $sauthConf['foursquare'] = array(
            'consumerSecret' => '',
            'consumerId' => '',
            'callbackUrl' => $siteUrl . $siteDir . '/index/auth/by/foursquare',
        );
        
        $sauthConf['flickr'] = array(
            'consumerKey' => '',
            'consumerSecret' => '',
            'userAuthorizationUrl' => 'http://flickr.com/services/auth/',
            'permission' => SAuth_Adapter_Flickr::PERMS_READ,
        );
        
        $sauthConf['gowalla'] = array(
            'consumerSecret' => '',
            'consumerId' => '',
            'callbackUrl' => $siteUrl . $siteDir . '/index/auth/by/gowalla',
        );
        
        $sauthConf['github'] = array(
            'consumerSecret' => '',
            'consumerId' => '',
            'callbackUrl' => $siteUrl . $siteDir . '/index/auth/by/github',
        );
        
        Zend_Registry::set('sauthConf', $sauthConf);
        
    }    
}

