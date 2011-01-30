<?php

class IndexController extends Zend_Controller_Action {

    public $config = array();
    
    public function init() {
        
        $this->config = array();
    }
    
    public function indexAction() {
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

