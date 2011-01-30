<?php

class IndexController extends Zend_Controller_Action {

    public $config = array();
    
    public function init() {
        
        $this->config = array(
            'id' => 'https://www.google.com/accounts/o8/id',
            'callbackUrl' => '/index/auth',
         );
    }
    
    public function indexAction() {
        
        $googleAuth = new SAuth_Provider_Google($this->config);
        if (!$googleAuth->isAuthorized()) {
            $this->view->auth = false;
        } else {
            $this->view->auth = true;
            $this->view->googleId = $googleAuth->getAuthId();
        }
    }
    
    public function authAction() {
        $googleAuth = new SAuth_Provider_Google($this->config);
        $this->view->auth = $googleAuth->auth();
    }
    
    public function logoutAction() {
        $this->_helper->viewRenderer->setNoRender();
        $googleAuth = new SAuth_Provider_Google($this->config);
        $googleAuth->clearAuth();
        $this->getResponse()->setRedirect('/');
    }

}

