<?php

/**  
 * @see SAuth_Adapter_Abstract 
 */
require_once 'Zend/OpenId/Extension.php';

class SAuth_Provider_Google_Extension extends Zend_OpenId_Extension {
    
    /**
     * @var array Request params
     */
    protected $_params = array();
    
    /**
     * Method to add additional data to OpenId 'checkid_immediate' or
     * 'checkid_setup' request. This method addes nothing but inherited class
     * may add additional data into request.
     * @param array &$params request's var/val pairs
     * @return bool
     */
    public function prepareRequest(&$params) {
        $attributeas = (array) $this->getParams();
        foreach ($attributeas as $key => $value) {
            $params[$key] = $value;
        }
        return true;
    }
    
    /**
     * Parses OpenId 'checkid_immediate' or 'checkid_setup' request,
     * extracts SREG variables and sets object properties to corresponding
     * values.
     *
     * @param array $params request's var/val pairs
     * @return bool
     */
    public function parseResponse($params) {
        return true;
    }
    
    /**
     * Setting attribute exchange extension
     * @param array $params
     * @return array
     */
    public function setParams(array $params = array()) {
            
        foreach ($params as $key => $value) {
            $this->_params[$key] = $value;
        }
        return $this->_params;
    }

    /**
     * Getting attribute exchange extension
     * @return array
     */
    public function getParams() {
            
        return $this->_params;
    }
}
