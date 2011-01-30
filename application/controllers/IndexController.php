<?php

class IndexController extends Zend_Controller_Action {

    public $config = array();
    
    public function init() {
        
        $this->config = array();
    }
    
    public function indexAction() {
        $googleAuth = new SAuth_Provider_Google($this->config['google']);
        $twitterAuth = new SAuth_Provider_Twitter($this->config['twitter']);
        if ($googleAuth->isAuthorized() || $twitterAuth->isAuthorized()) {
            $this->view->isAuth = true;
            if ($googleAuth->isAuthorized()) {
                $this->view->id = $googleAuth->getAuthId();
            }
            if ($twitterAuth->isAuthorized()) {
                $this->view->id = $twitterAuth->getAuthId();
            }
        } else {
            $this->view->isAuth = false;
        }
    }
    
    public function authAction() {
        $authBy = $this->getResponse()->getParam('by') ? $this->getResponse()->getParam('by') : 'google';
        switch ($authBy) {
            case 'google':
                $googleAuth = new SAuth_Provider_Google($this->config['google']);
                $this->view->auth = $googleAuth->auth();
                break;
            case 'twitter':
                $twitterAuth = new SAuth_Provider_Twitter($this->config['twitter']);
                $this->view->auth = $twitterAuth->auth();
                break;
        }
    }
    
    public function logoutAction() {
        $this->_helper->viewRenderer->setNoRender();
        $googleAuth = new SAuth_Provider_Google($this->config);
        $googleAuth->clearAuth();
        $this->getResponse()->setRedirect('/');
    }

}

