SAuth
=====

**This library is open source. Please help me by forking the project and adding to it.**


Social authentication library for Zend Framework
-----------------------------------------------

Includes libraries for next social services:

* Facebook
* Twitter
* Google
* Foursquare
* Vkontakte
* Mail.ru
* Flickr
* Gowalla
* Github
* Skyrock

Getting Started
---------------

Simple example of authentication

    public function authAction() {
        
        $parameters = array(
            'consumerId' => 'YOUR_CONSUMER_ID',
            'consumerKey' => 'YOUR_CONSUMER_KEY',
            'consumerSecret' => 'YOUR_CONSUMER_SECRET',
            'callbackUrl' => 'http://site.com/call_back_url',
            'scope' => array(
                 'user_about_me', 'email',
            ),
        );
        
        $auth = Zend_Auth::getInstance();

        /**
         * or SAuth_Adapter_Twitter
         * or SAuth_Adapter_Foursquare
         * or SAuth_Adapter_Google
         * ...
         */
        $adapter = new SAuth_Adapter_Facebook($parameters);
        
        $result  = $auth->authenticate($adapter);
        
        if ($result->isValid()) {
            
            echo 'Success!';
            
        } else {
            
            echo 'Failed!';
            echo $result->getMessages();
            
        }
        
    }
   
Library also retrieve user data from social service

    public functoin indexAction() {
        
        $auth = Zend_Auth::getInstance();
        
        if ($auth->hasIdentity()) {
                
            /**
             * User data from service, such as login, email, id, name etc.
             */
            $userParameters = $auth->getIdentity();
        
        }
    }
    
Demo
----

[Demo](http://dnixa.com/sauth/demos/public_html/)

