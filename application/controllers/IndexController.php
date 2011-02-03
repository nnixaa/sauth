<?php

class IndexController extends Zend_Controller_Action {

    public $config = array();
    
    public function init() {
        
        $this->config['google'] = array(
            'id' => 'https://www.google.com/accounts/o8/id',
            'callbackUrl' => '/index/auth',
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
            'callbackUrl' => 'http://dnixa.tmweb.ru/index/auth',
        );
          
        $this->config['facebook'] = array(
            'consumerKey' => '327c9cbf33902ff250f8248519fe09d9',
            'consumerSecret' => '4b5ebef60169f606d6a3763df3173b23',
            'clientId' => '184454904920383',
            'userAuthorizationUrl' => 'https://www.facebook.com/dialog/oauth',
            'accessTokenUrl' => 'https://graph.facebook.com/oauth/access_token',
            'redirectUri' => 'http://dnixa.tmweb.ru/index/auth',
            'scope' => array(
                 'user_about_me', 'user_activities',
            ),
        );
    }
    
    public function indexAction() {
            
        $googleAuth = new SAuth_Provider_Google($this->config['google']);
        $twitterAuth = new SAuth_Provider_Twitter($this->config['twitter']);
        $facebookAuth = new SAuth_Provider_Facebook($this->config['facebook']);
        if ($googleAuth->isAuthorized() || $twitterAuth->isAuthorized() || $facebookAuth->isAuthorized()) {
            $this->view->isAuth = true;
            if ($googleAuth->isAuthorized()) {
                $this->view->id = $googleAuth->getAuthId();
                $this->view->login = $googleAuth->getUserParam('openid_ext1_value_email');
                
            }
            if ($twitterAuth->isAuthorized()) {
                $this->view->id = $twitterAuth->getAuthId();
                $this->view->login = $twitterAuth->getUserParameters('screen_name');
            }
            if ($facebookAuth->isAuthorized()) {
                $this->view->id = $facebookAuth->getAuthId();
                $this->view->login = $facebookAuth->getUserParameters('email');
            }
        } else {
            $this->view->isAuth = false;
        }
    }
    
    public function authAction() {
            
        $authBy = $this->getRequest()->getParam('by') ? $this->getRequest()->getParam('by') : 'google';
        switch ($authBy) {
            case 'google':
                $this->config['google']['callbackUrl'] .= '/by/google';
                $googleAuth = new SAuth_Provider_Google($this->config['google']);
                $this->view->auth = $googleAuth->auth();
                break;
            case 'twitter':
                $this->config['twitter']['callbackUrl'] .= '/by/twitter';
                $twitterAuth = new SAuth_Provider_Twitter($this->config['twitter']);
                $this->view->auth = $twitterAuth->auth();
                break;
            case 'facebook':
                $this->config['facebook']['redirectUri'] .= '/by/facebook';
                $facebookAuth = new SAuth_Provider_Facebook($this->config['facebook']);
                $this->view->auth = $facebookAuth->auth();
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
        $this->getResponse()->setRedirect('/');
    }

}

