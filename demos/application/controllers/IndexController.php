<?php

class IndexController extends Zend_Controller_Action {

    public $config = array();
    
    public function init() {
        $this->config = Zend_Registry::get('sauthConf');
    }
    
    public function indexAction() {
    }
    
    public function authAction() {
        $authBy = $this->getRequest()->getParam('by') ? $this->getRequest()->getParam('by') : 'google';
    }
    
    public function logoutAction() {
        $this->_helper->viewRenderer->setNoRender();
        $this->getResponse()->setRedirect('/');
    }

}
