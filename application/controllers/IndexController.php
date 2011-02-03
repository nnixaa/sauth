<?php

class IndexController extends Zend_Controller_Action {

    public $config = array();
    
    public function init() {
        
        $this->config = array(
            'apiId' => '2157310',
        );
    }
    
    public function indexAction() {
        
        $vkontakteAuth = new SAuth_Provider_Vkontakte($this->config);
        if (!$vkontakteAuth->isAuthorized()) {
            $this->view->auth = false;
        } else {
            $this->view->auth = true;
            $this->view->facebookId = $vkontakteAuth->getAuthId();
        }
    }
    
    public function authAction() {
        $vkontakteAuth = new SAuth_Provider_Vkontakte($this->config);
        $this->view->auth = $vkontakteAuth->auth();
    }
    
    public function logoutAction() {
        $this->_helper->viewRenderer->setNoRender();
        $vkontakteAuth = new SAuth_Provider_Vkontakte($this->config);
        $vkontakteAuth->clearAuth();
        $this->getResponse()->setRedirect('/');
    }

}

