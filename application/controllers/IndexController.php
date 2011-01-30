<?php

class IndexController extends Zend_Controller_Action {

    public $config = array();
    
    public function init() {
        
        $this->config = array(
            'requestScheme' => Zend_Oauth::REQUEST_SCHEME_HEADER,
            'consumerKey' => 'GAgdRjJmORMNtfEQDzoWWw',
            'consumerSecret' => 'HnwlFxrA60206FNv8TYG1jxjJdHeB24E0tTmBjsDwQ',
            'version' => '1.0',
            'requestTokenUrl' => 'https://api.twitter.com/oauth/request_token',
            'userAuthorizationUrl' => 'https://api.twitter.com/oauth/authorize',
            'accessTokenUrl' => 'https://api.twitter.com/oauth/access_token',
            'callbackUrl' => 'http://nixa.ath.cx/index/auth'
        );
    }
    
    public function indexAction() {
        
        $twitterAuth = new SAuth_Provider_Twitter($this->config);
        if (!$twitterAuth->isAuthorized()) {
            $this->view->auth = false;
        } else {
            $this->view->auth = true;
            $this->view->twitterId = $twitterAuth->getAuthId();
            $this->view->twitterParam = $twitterAuth->getTokenParam('screen_name');
        }
    }
    
    public function authAction() {
        $twitterAuth = new SAuth_Provider_Twitter($this->config);
        $this->view->auth = $twitterAuth->auth();
    }
    
    public function logoutAction() {
        $this->_helper->viewRenderer->setNoRender();
        $twitterAuth = new SAuth_Provider_Twitter($this->config);
        $twitterAuth->clearAuth();
        $this->getResponse()->setRedirect('/');
    }

}

