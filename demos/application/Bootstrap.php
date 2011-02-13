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
        
        $sauthConf['google'] = array(
            'id' => 'https://www.google.com/accounts/o8/id',
            'callbackUrl' => '/index/auth/by/google',
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
            'callbackUrl' => 'http://dnixa.tmweb.ru/index/auth/by/twitter',
        );
          
        $sauthConf['facebook'] = array(
            'consumerId' => '',
            'consumerKey' => '',
            'consumerSecret' => '',
            'callbackUrl' => 'http://dnixa.tmweb.ru/index/auth/by/facebook',
            'scope' => array(
                 'user_about_me', 'email',
            ),
        );
        
        $sauthConf['vkontakte'] = array(
            'consumerId' => '',
            'consumerSecret' => '',
            'userAuthorizationUrl' => 'http://dnixa.tmweb.ru/index/auth/by/vkontakte',
            'callbackUrl' => 'http://dnixa.tmweb.ru',
        );
        
        $sauthConf['mailru'] = array(
            'consumerId' => '',
            'privateKey' => '',
            'consumerSecret' => '',
            'callbackUrl' => 'http://dnixa.tmweb.ru/index/auth/by/mailru',
        );
        
        $sauthConf['foursquare'] = array(
            'consumerSecret' => '',
            'consumerId' => '',
            'callbackUrl' => 'http://dnixa.tmweb.ru/index/auth/by/foursquare',
        );
        Zend_Registry::set('sauthConf', $sauthConf);
        
    }    
}

