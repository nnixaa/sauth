<?php

class IndexController extends Zend_Controller_Action {

    public $config = array();
    
    
    public function init() {
        
        $this->config = Zend_Registry::get('sauthConf');
        
    }
    
    public function indexAction() {
        
        $this->view->vkAppId = $this->config['vkontakte']['consumerId'];
        $this->view->vkAuthUrl = $this->config['vkontakte']['userAuthorizationUrl'];
        
        $sauthProvider = new SAuth_Provider();
        if ($sauthProvider->isAuthorized()) {
                
            $this->view->auth = true;
            $this->view->parameters = $sauthProvider->getCurrentProvider()->getUserParameters();
        
        } else {
            
            $this->view->auth = false;
        }
    }
    
    public function authAction() {
            
        $provider = $this->getRequest()->getParam('by') ? $this->getRequest()->getParam('by') : 'google';
        $providerClass = 'SAuth_Provider_' . ucfirst($provider);
        
        $sauthProvider = new SAuth_Provider();
        $sauthProvider->setUpProvider($providerClass, $this->config[$provider]);
        
        if ($sauthProvider->authenticate()) {
            
            $this->view->auth = true;
            
        } else {
            
            $this->view->auth = false;
            
        }
        
    }
    
    public function logoutAction() {
        
        $sauthProvider = new SAuth_Provider();
        
        if ($sauthProvider->isAuthorized()) {
            $sauthProvider->getCurrentProvider()->clearAuth();
        }
        
        $this->_helper->viewRenderer->setNoRender();
        $this->getResponse()->setRedirect('/');
    }

}
