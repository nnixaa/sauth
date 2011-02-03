<?php

class IndexController extends Zend_Controller_Action {

    public $config = array();
    
    public function init() {
        
        $this->config = array(
            'consumerKey' => '327c9cbf33902ff250f8248519fe09d9',
            'consumerSecret' => '4b5ebef60169f606d6a3763df3173b23',
            'clientId' => '184454904920383',
            'userAuthorizationUrl' => 'https://www.facebook.com/dialog/oauth',
            'accessTokenUrl' => 'https://graph.facebook.com/oauth/access_token',
            'redirectUri' => 'http://dnixa.tmweb.ru/index/auth',
            'scope' => array(
                 'user_about_me', 'user_activities',
            ),
        );
    }
    
    public function indexAction() {
        
        $facebookAuth = new SAuth_Provider_Facebook($this->config);
        if (!$facebookAuth->isAuthorized()) {
            $this->view->auth = false;
        } else {
            $this->view->auth = true;
            $this->view->facebookId = $facebookAuth->getAuthId();
        }
    }
    
    public function authAction() {
        $facebookAuth = new SAuth_Provider_Facebook($this->config);
        $this->view->auth = $facebookAuth->auth();
    }
    
    public function logoutAction() {
        $this->_helper->viewRenderer->setNoRender();
        $facebookAuth = new SAuth_Provider_Facebook($this->config);
        $facebookAuth->clearAuth();
        $this->getResponse()->setRedirect('/');
    }

}

