<?php

class IndexController extends Zend_Controller_Action {

    public $config = array();
    
    public function init() {
        
        $this->config = array(
            'callbackUrl'       => 'http://kurapov.name',
            'siteUrl'           => 'https://www.google.com/accounts/',
            'authorizeUrl'      => 'https://www.google.com/accounts/OAuthAuthorizeToken',
            'requestTokenUrl'  => 'https://www.google.com/accounts/OAuthGetRequestToken',
            'accessTokenUrl'    => 'https://www.google.com/accounts/OAuthGetAccessToken',
            'consumerKey'       => 'dnixa.tmweb.ru',
            'consumerSecret'    => 'fZfydAcVoEZUw+AaPKqMDG59',
            'scope' => 'http://www-opensocial.googleusercontent.com/api/people/',
         );
    }
    
    public function indexAction() {
        
    }
    
    public function authAction() {
        $consumer = new Zend_Oauth_Consumer($this->config);
    }
    
    public function logoutAction() {
        $this->_helper->viewRenderer->setNoRender();
        $this->getResponse()->setRedirect('/');
    }

}

