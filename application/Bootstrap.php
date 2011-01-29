<?php

class Bootstrap extends Zend_Application_Bootstrap_Bootstrap
{
    
    protected function _initApp() {
        $autoloader = Zend_Loader_Autoloader::getInstance();
        $autoloader->registerNamespace('SAuth_');
    }   

}

