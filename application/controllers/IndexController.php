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
    }
    
    public function indexAction() {
            
        $googleAuth = new SAuth_Provider_Google($this->config['google']);
        $twitterAuth = new SAuth_Provider_Twitter($this->config['twitter']);
        if ($googleAuth->isAuthorized() || $twitterAuth->isAuthorized()) {
            $this->view->isAuth = true;
            if ($googleAuth->isAuthorized()) {
                $this->view->id = $googleAuth->getAuthId();
                $this->view->login = $googleAuth->getUserParam('openid_ext1_value_email');
                
            }
            if ($twitterAuth->isAuthorized()) {
                $this->view->id = $twitterAuth->getAuthId();
                $this->view->login = $twitterAuth->getUserParam('screen_name');
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
        }
    }
    
    public function logoutAction() {
            
        $this->_helper->viewRenderer->setNoRender();
        
        $googleAuth = new SAuth_Provider_Google($this->config['google']);
        $googleAuth->clearAuth();
        $twitterAuth = new SAuth_Provider_Twitter($this->config['twitter']);
        $twitterAuth->clearAuth();
        $this->getResponse()->setRedirect('/');
    }

}

