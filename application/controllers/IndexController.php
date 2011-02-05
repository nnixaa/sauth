<?php

class IndexController extends Zend_Controller_Action {

    public $config = array();
    
    public function init() {
        
        $this->config = array(
            'consumerSecret' => '5TMLM0TY3AXFZI1CQHPBDCWZJ0RQZDBKUAGQHHLHJE1I43I2',
            'clientId' => '5THSZIOOWVTDJNGB0I3LPWVJYQ4QILZZSVCT2Q3G3FTQDUQ3',
            'userAuthorizationUrl' => 'https://foursquare.com/oauth2/authorize',
            'accessTokenUrl' => 'https://foursquare.com/oauth2/access_token',
            'redirectUri' => 'http://dnixa.tmweb.ru/index/auth',
        );
    }
    
    public function indexAction() {
        
        $foursquareAuth = new SAuth_Provider_Foursquare($this->config);
        if (!$foursquareAuth->isAuthorized()) {
            $this->view->auth = false;
        } else {
            $this->view->auth = true;
            $this->view->foursquareId = $foursquareAuth->getAuthId();
            Zend_Debug::dump($foursquareAuth->getUserParameters());
        }
    }
    
    public function authAction() {
        $foursquareAuth = new SAuth_Provider_Foursquare($this->config);
        $this->view->auth = $foursquareAuth->auth();
    }
    
    public function logoutAction() {
        $this->_helper->viewRenderer->setNoRender();
        $foursquareAuth = new SAuth_Provider_Foursquare($this->config);
        $foursquareAuth->clearAuth();
        $this->getResponse()->setRedirect('/');
    }

}

