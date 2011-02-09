<?php

/**
 * Interface class for Sauth libraries
 */
interface SAuth_Provider_Interface {
    
    /**
     * Authorized user
     * @param array $config
     * @return true
     */
    public function auth(array $config = array());    
    
    /**
     * Returns authorization flag
     * @return bool
     */
    public function isAuthorized();

    /**
     * Getting authentication identification
     * @return false|int User ID
     */
    public function getAuthId();
    
    /**
     * TODO: Can't select multi-level arrays
     * Returns user parameters
     * @param string $key
     * @return mixed
     */
    public function getUserParameters($key = null);
    
    /**
     * Setting user parameters in session
     * @param array $userParameters
     * @return array
     */
    public function setUserParameters(array $userParameters);
    
    /**
     * Clear saved access token
     * @return array Configuration array
     */
    public function clearAuth();
    
    /**
     * Setting configuration
     * @param array $config
     */
    public function setConfig(array $config = array());
    
    /**
     * Getting configuration
     * @param string $key
     * @return array Configuration array
     */
    public function getConfig($key = null);
    
    /**
     * Gettion session live time
     * @return int
     */
    public function getSessionLiveTime();
}
