<?php

class IndexController extends Zend_Controller_Action {

    public $config = array();
    
    public function init() {
        
        $this->config = array(
            'consumerSecret' => '3a2381491f9dc192048ef286e6072d2c',
            'privateKey' => 'd2eaa0a682c17da8afd94377c1f55e6c',
            'clientId' => '586934',
            'userAuthorizationUrl' => 'https://connect.mail.ru/oauth/authorize',
            'accessTokenUrl' => 'https://connect.mail.ru/oauth/token',
            'redirectUri' => 'http://dnixa.tmweb.ru/index/auth',
        );
    }
    
    public function indexAction() {
        
        $mailruAuth = new SAuth_Provider_Mailru($this->config);
        if (!$mailruAuth->isAuthorized()) {
            $this->view->auth = false;
        } else {
            $this->view->auth = true;
            $this->view->mailruId = $mailruAuth->getAuthId();
        }
    }
    
    public function authAction() {
        $mailruAuth = new SAuth_Provider_Mailru($this->config);
        $this->view->auth = $mailruAuth->auth();
    }
    
    public function logoutAction() {
        $this->_helper->viewRenderer->setNoRender();
        $mailruAuth = new SAuth_Provider_Mailru($this->config);
        $mailruAuth->clearAuth();
        $this->getResponse()->setRedirect('/');
    }

}

