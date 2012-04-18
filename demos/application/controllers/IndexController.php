<?php

class IndexController extends Zend_Controller_Action {

    public $config = array();
    
    
    public function init() {
        
        $this->config = Zend_Registry::get('sauthConf');
        $bootstrap = $this->getInvokeArg('bootstrap');
        $siteDir = $bootstrap->getOption('siteDir');
        $this->view->siteDir = $siteDir;
    }
    
    public function indexAction() {
        
        $auth = Zend_Auth::getInstance();
        
        if ($auth->hasIdentity()) {
                
            $this->view->auth = true;
            $this->view->userData = $auth->getIdentity();
        
        } else {
            
            $this->view->auth = false;
        }
    }
    
	/**
	 * This method will be call twice
	 * First time when user was opened authentication window
	 * Second time when social service will redirect user back with success or error
	 */
    public function authAction() {
            
        $auth = Zend_Auth::getInstance();
        
        if ($auth->hasIdentity()) {
            $this->getResponse()->setRedirect($this->view->siteDir);
        }
        
        $adapterName = $this->getRequest()->getParam('by') ? $this->getRequest()->getParam('by') : 'google';
        $adapterClass = 'SAuth_Adapter_' . ucfirst($adapterName);
        
        $adapter = new $adapterClass($this->config[$adapterName]);
        
        $result  = $auth->authenticate($adapter);
        
        if ($result->isValid()) {
            
            $this->view->auth = true;
            
        } else {
            
            $this->view->auth = false;
            $this->view->errors = $result->getMessages();
        }
    }
    
    public function logoutAction() {
        
        $auth = Zend_Auth::getInstance();
        $auth->clearIdentity();

        $this->getResponse()->setRedirect($this->view->siteDir);
    }

}
