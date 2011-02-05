<?php

class IndexController extends Zend_Controller_Action {

    public $config = array();
    
    public function init() {
        
        $this->config['google'] = array(
            'id' => 'https://www.google.com/accounts/o8/id',
            'callbackUrl' => '/index/auth/by/google',
            'exchangeExtension' => array(
                'openid.ns.ax' => 'http://openid.net/srv/ax/1.0',
                'openid.ax.mode' => 'fetch_request',
                'openid.ax.type.email' => 'http://axschema.org/contact/email',
                'openid.ax.required' => 'email',
            ),
        );
        
        $this->config['twitter'] = array(
            'requestScheme' => Zend_Oauth::REQUEST_SCHEME_HEADER,
            'consumerKey' => 'GAgdRjJmORMNtfEQDzoWWw',
            'consumerSecret' => 'HnwlFxrA60206FNv8TYG1jxjJdHeB24E0tTmBjsDwQ',
            'version' => '1.0',
            'requestTokenUrl' => 'https://api.twitter.com/oauth/request_token',
            'userAuthorizationUrl' => 'https://api.twitter.com/oauth/authorize',
            'accessTokenUrl' => 'https://api.twitter.com/oauth/access_token',
            'callbackUrl' => 'http://dnixa.tmweb.ru/index/auth/by/twitter',
        );
          
        $this->config['facebook'] = array(
            'consumerKey' => '327c9cbf33902ff250f8248519fe09d9',
            'consumerSecret' => '4b5ebef60169f606d6a3763df3173b23',
            'clientId' => '184454904920383',
            'userAuthorizationUrl' => 'https://www.facebook.com/dialog/oauth',
            'accessTokenUrl' => 'https://graph.facebook.com/oauth/access_token',
            'redirectUri' => 'http://dnixa.tmweb.ru/index/auth/by/facebook',
            'scope' => array(
                 'user_about_me', 'email',
            ),
        );
        
        $this->config['vkontakte'] = array(
            'apiId' => '2157310',
            'apiSecret' => 'ABGeZmiYE46jWvRaeJuD',
            'redirectUrl' => 'http://dnixa.tmweb.ru',
            'userAuthorizationUrl' => 'http://dnixa.tmweb.ru/index/auth/by/vkontakte',
        );
        
        $this->config['mailru'] = array(
            'consumerSecret' => '3a2381491f9dc192048ef286e6072d2c',
            'privateKey' => 'd2eaa0a682c17da8afd94377c1f55e6c',
            'clientId' => '586934',
            'userAuthorizationUrl' => 'https://connect.mail.ru/oauth/authorize',
            'accessTokenUrl' => 'https://connect.mail.ru/oauth/token',
            'redirectUri' => 'http://dnixa.tmweb.ru/index/auth/by/mailru',
        );
    }
    
    public function indexAction() {
            
        $googleAuth = new SAuth_Provider_Google($this->config['google']);
        $twitterAuth = new SAuth_Provider_Twitter($this->config['twitter']);
        $facebookAuth = new SAuth_Provider_Facebook($this->config['facebook']);
        $vkontakteAuth = new SAuth_Provider_Vkontakte($this->config['vkontakte']);
        $mailruAuth = new SAuth_Provider_Mailru($this->config['mailru']);
        
        $this->view->vkAppId = $this->config['vkontakte']['apiId'];
        $this->view->vkAuthUrl = $this->config['vkontakte']['userAuthorizationUrl'];
        
        if ($googleAuth->isAuthorized() || $twitterAuth->isAuthorized() || $facebookAuth->isAuthorized()
            || $vkontakteAuth->isAuthorized() || $mailruAuth->isAuthorized()) {
                
            $this->view->isAuth = true;
            if ($googleAuth->isAuthorized()) {
                $this->view->id = $googleAuth->getAuthId();
                $this->view->login = $googleAuth->getUserParameters('openid_ext1_value_email');
                
            }
            if ($twitterAuth->isAuthorized()) {
                $this->view->id = $twitterAuth->getAuthId();
                $this->view->login = $twitterAuth->getUserParameters('screen_name');
            }
            if ($facebookAuth->isAuthorized()) {
                $this->view->id = $facebookAuth->getAuthId();
                $this->view->login = $facebookAuth->getUserParameters('email');
            }
            if ($vkontakteAuth->isAuthorized()) {
                $this->view->id = $vkontakteAuth->getAuthId();
                $this->view->login = $vkontakteAuth->getUserParameters('first_name');
            }
            if ($mailruAuth->isAuthorized()) {
                $this->view->id = $mailruAuth->getAuthId();
                $this->view->login = $mailruAuth->getUserParameters('email');
            }
        } else {
            $this->view->isAuth = false;
        }
    }
    
    public function authAction() {
            
        $authBy = $this->getRequest()->getParam('by') ? $this->getRequest()->getParam('by') : 'google';
        switch ($authBy) {
            case 'google':
                $googleAuth = new SAuth_Provider_Google($this->config['google']);
                $this->view->auth = $googleAuth->auth();
                break;
            case 'twitter':
                $twitterAuth = new SAuth_Provider_Twitter($this->config['twitter']);
                $this->view->auth = $twitterAuth->auth();
                break;
            case 'facebook':
                $facebookAuth = new SAuth_Provider_Facebook($this->config['facebook']);
                $this->view->auth = $facebookAuth->auth();
                break;
            case 'vkontakte':
                $vkontakteAuth = new SAuth_Provider_Vkontakte($this->config['vkontakte']);
                $this->view->auth = $vkontakteAuth->auth();
                break;
            case 'mailru':
                $mailruAuth = new SAuth_Provider_Mailru($this->config['mailru']);
                $this->view->auth = $mailruAuth->auth();
                break;
        }
    }
    
    public function logoutAction() {
            
        $this->_helper->viewRenderer->setNoRender();
        
        $googleAuth = new SAuth_Provider_Google($this->config['google']);
        $googleAuth->clearAuth();
        $twitterAuth = new SAuth_Provider_Twitter($this->config['twitter']);
        $twitterAuth->clearAuth();
        $facebookAuth = new SAuth_Provider_Facebook($this->config['facebook']);
        $facebookAuth->clearAuth();
        $vkontakteAuth = new SAuth_Provider_Vkontakte($this->config['vkontakte']);
        $vkontakteAuth->clearAuth();
        $mailruAuth = new SAuth_Provider_Mailru($this->config['mailru']);
        $mailruAuth->clearAuth();
        $this->getResponse()->setRedirect('/');
    }

}
