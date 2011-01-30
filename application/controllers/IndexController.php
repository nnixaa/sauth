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
    }
    
    public function authAction() {
        $auth = new SAuth_Provider_Google($this->config);
        if ($auth->auth()) {
            Zend_Debug::dump($auth->getAuthId());
        }
    }
    
    public function logoutAction() {
        $this->_helper->viewRenderer->setNoRender();
        $this->getResponse()->setRedirect('/');
    }

}

