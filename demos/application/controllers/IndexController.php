<?php

class IndexController extends Zend_Controller_Action {

    public $config = array();
    
    public function init() {
        $this->config = Zend_Registry::get('sauthConf');
    }
    
    public function indexAction() {
            
        $googleAuth = new SAuth_Provider_Google($this->config['google']);
        $twitterAuth = new SAuth_Provider_Twitter($this->config['twitter']);
        $facebookAuth = new SAuth_Provider_Facebook($this->config['facebook']);
        $vkontakteAuth = new SAuth_Provider_Vkontakte($this->config['vkontakte']);
        $mailruAuth = new SAuth_Provider_Mailru($this->config['mailru']);
        $foursquareAuth = new SAuth_Provider_Foursquare($this->config['foursquare']);
        
        $this->view->vkAppId = $this->config['vkontakte']['consumerId'];
        $this->view->vkAuthUrl = $this->config['vkontakte']['userAuthorizationUrl'];
        
        if ($googleAuth->isAuthorized() || $twitterAuth->isAuthorized() || $facebookAuth->isAuthorized()
            || $vkontakteAuth->isAuthorized() || $mailruAuth->isAuthorized() || $foursquareAuth->isAuthorized()) {
                
            $this->view->isAuth = true;
            if ($googleAuth->isAuthorized()) {
                $this->view->id = $googleAuth->getAuthId();
                $this->view->login = $googleAuth->getUserParameters('openid_ext1_value_email');
                
            }
            if ($twitterAuth->isAuthorized()) {
                $this->view->id = $twitterAuth->getAuthId();
                $this->view->login = $twitterAuth->getUserParameters('screen_name');
            }
            if ($facebookAuth->isAuthorized()) {
                $this->view->id = $facebookAuth->getAuthId();
                $this->view->login = $facebookAuth->getUserParameters('email');
            }
            if ($vkontakteAuth->isAuthorized()) {
                $this->view->id = $vkontakteAuth->getAuthId();
                $this->view->login = $vkontakteAuth->getUserParameters('first_name');
            }
            if ($mailruAuth->isAuthorized()) {
                $this->view->id = $mailruAuth->getAuthId();
                $this->view->login = $mailruAuth->getUserParameters('email');
            }
            if ($foursquareAuth->isAuthorized()) {
                $this->view->id = $foursquareAuth->getAuthId();
                $this->view->login = $foursquareAuth->getUserParameters('firstName');
            }
        } else {
            $this->view->isAuth = false;
        }
    }
    
    public function authAction() {
            
        $authBy = $this->getRequest()->getParam('by') ? $this->getRequest()->getParam('by') : 'google';
        switch ($authBy) {
            case 'google':
                $googleAuth = new SAuth_Provider_Google($this->config['google']);
                $this->view->auth = $googleAuth->authenticate();
                break;
            case 'twitter':
                $twitterAuth = new SAuth_Provider_Twitter($this->config['twitter']);
                $this->view->auth = $twitterAuth->authenticate();
                break;
            case 'facebook':
                $facebookAuth = new SAuth_Provider_Facebook($this->config['facebook']);
                $this->view->auth = $facebookAuth->authenticate();
                break;
            case 'vkontakte':
                $vkontakteAuth = new SAuth_Provider_Vkontakte($this->config['vkontakte']);
                $this->view->auth = $vkontakteAuth->authenticate();
                break;
            case 'mailru':
                $mailruAuth = new SAuth_Provider_Mailru($this->config['mailru']);
                $this->view->auth = $mailruAuth->authenticate();
                break;
            case 'foursquare':
                $foursquareAuth = new SAuth_Provider_Foursquare($this->config['foursquare']);
                $this->view->auth = $foursquareAuth->authenticate();
                break;
        }
    }
    
    public function logoutAction() {
            
        $this->_helper->viewRenderer->setNoRender();
        
        $googleAuth = new SAuth_Provider_Google($this->config['google']);
        $googleAuth->clearAuth();
        $twitterAuth = new SAuth_Provider_Twitter($this->config['twitter']);
        $twitterAuth->clearAuth();
        $facebookAuth = new SAuth_Provider_Facebook($this->config['facebook']);
        $facebookAuth->clearAuth();
        $vkontakteAuth = new SAuth_Provider_Vkontakte($this->config['vkontakte']);
        $vkontakteAuth->clearAuth();
        $mailruAuth = new SAuth_Provider_Mailru($this->config['mailru']);
        $mailruAuth->clearAuth();
        $foursquareAuth = new SAuth_Provider_Foursquare($this->config['foursquare']);
        $foursquareAuth->clearAuth();
        $this->getResponse()->setRedirect('/');
    }

}
