<?php
/**
 * Zend Framework
 *
 * LICENSE
 *
 * This source file is subject to the new BSD license that is bundled
 * with this package in the file LICENSE.txt.
 * It is also available through the world-wide-web at this URL:
 * http://framework.zend.com/license/new-bsd
 * If you did not receive a copy of the license and are unable to
 * obtain it through the world-wide-web, please send an email
 * to license@zend.com so we can send you a copy immediately.
 *
 * @category   Zend
 * @package    Zend_OpenId
 * @subpackage Zend_OpenId_Consumer
 * @copyright  Copyright (c) 2005-2009 Zend Technologies USA Inc. (http://www.zend.com)
 * @license    http://framework.zend.com/license/new-bsd     New BSD License
 */

/**
 * Modified openid consumer to be spec 2.0 compliant
 *
 * @author Akeem Philbert <akeem.philbert@gmail.com>
 * @copyright Copyright (c) 2009 Akeem Philbert
 */
class Ak33m_OpenId_Consumer extends Zend_OpenId_Consumer
{
    /**
     * Performs discovery of identity and finds OpenID URL, OpenID server URL
     * and OpenID protocol version. Returns true on succees and false on
     * failure.
     *
     * @param string &$id OpenID identity URL
     * @param string &$server OpenID server URL
     * @param float &$version OpenID protocol version
     * @return bool
     * @todo OpenID 2.0 (7.3) XRI and Yadis discovery
     */
    protected function _discovery(&$id, &$server, &$version)
    {
        $realId = $id;
        if ($this->_storage->getDiscoveryInfo(
                $id,
                $realId,
                $server,
                $version,
                $expire)) {
            $id = $realId;
            return true;
        }

        /* TODO: OpenID 2.0 (7.3) XRI and Yadis discovery */

        /* HTML-based discovery */
        $response = $this->_httpRequest($id, 'GET', array(), $status);
        if ($status != 200 || !is_string($response)) {
            return false;
        }
        if (preg_match(
                '/<link[^>]*rel=(["\'])[ \t]*(?:[^ \t"\']+[ \t]+)*?openid2.provider[ \t]*[^"\']*\\1[^>]*href=(["\'])([^"\']+)\\2[^>]*\/?>/i',
                $response,
                $r)) {
            $version = 2.0;
            $server = $r[3];
        } else if (preg_match(
                '/<link[^>]*href=(["\'])([^"\']+)\\1[^>]*rel=(["\'])[ \t]*(?:[^ \t"\']+[ \t]+)*?openid2.provider[ \t]*[^"\']*\\3[^>]*\/?>/i',
                $response,
                $r)) {
            $version = 2.0;
            $server = $r[2];
        } else if (preg_match(
                '/<link[^>]*rel=(["\'])[ \t]*(?:[^ \t"\']+[ \t]+)*?openid.server[ \t]*[^"\']*\\1[^>]*href=(["\'])([^"\']+)\\2[^>]*\/?>/i',
                $response,
                $r)) {
            $version = 1.1;
            $server = $r[3];
        } else if (preg_match(
                '/<link[^>]*href=(["\'])([^"\']+)\\1[^>]*rel=(["\'])[ \t]*(?:[^ \t"\']+[ \t]+)*?openid.server[ \t]*[^"\']*\\3[^>]*\/?>/i',
                $response,
                $r)) {
            $version = 1.1;
            $server = $r[2];
            }
            else if (preg_match('/<URI>([^<]+)<\/URI>/i', $response, $r)) {
              $version = 2.0;
              $server = $r[1];
        } else {

            return false;
        }
        if ($version >= 2.0) {
            if (preg_match(
                    '/<link[^>]*rel=(["\'])[ \t]*(?:[^ \t"\']+[ \t]+)*?openid2.local_id[ \t]*[^"\']*\\1[^>]*href=(["\'])([^"\']+)\\2[^>]*\/?>/i',
                    $response,
                    $r)) {
                $realId = $r[3];
            } else if (preg_match(
                    '/<link[^>]*href=(["\'])([^"\']+)\\1[^>]*rel=(["\'])[ \t]*(?:[^ \t"\']+[ \t]+)*?openid2.local_id[ \t]*[^"\']*\\3[^>]*\/?>/i',
                    $response,
                    $r)) {
                $realId = $r[2];
            }
        } else {
            if (preg_match(
                    '/<link[^>]*rel=(["\'])[ \t]*(?:[^ \t"\']+[ \t]+)*?openid.delegate[ \t]*[^"\']*\\1[^>]*href=(["\'])([^"\']+)\\2[^>]*\/?>/i',
                    $response,
                    $r)) {
                $realId = $r[3];
            } else if (preg_match(
                    '/<link[^>]*href=(["\'])([^"\']+)\\1[^>]*rel=(["\'])[ \t]*(?:[^ \t"\']+[ \t]+)*?openid.delegate[ \t]*[^"\']*\\3[^>]*\/?>/i',
                    $response,
                    $r)) {
                $realId = $r[2];
            }
        }

        $expire = time() + 60 * 60;
        $this->_storage->addDiscoveryInfo($id, $realId, $server, $version, $expire);
        $id = $realId;
        return true;
    }

    /**
     * Performs check of OpenID identity.
     *
     * This is the first step of OpenID authentication process.
     * On success the function does not return (it does HTTP redirection to
     * server and exits). On failure it returns false.
     *
     * @param bool $immediate enables or disables interaction with user
     * @param string $id OpenID identity
     * @param string $returnTo HTTP URL to redirect response from server to
     * @param string $root HTTP URL to identify consumer on server
     * @param mixed $extensions extension object or array of extensions objects
     * @param Zend_Controller_Response_Abstract $response an optional response
     *  object to perform HTTP or HTML form redirection
     * @return bool
     */
    protected function _checkId($immediate, $id, $returnTo=null, $root=null,
        $extensions=null, Zend_Controller_Response_Abstract $response = null)
    {
        $this->_setError('');

        if (!Zend_OpenId::normalize($id)) {
            $this->_setError("Normalisation failed");
            return false;
        }
        $claimedId = $id;

        if (!$this->_discovery($id, $server, $version)) {
            $this->_setError("Discovery failed: " . $this->getError());
            return false;
        }
        if (!$this->_associate($server, $version)) {
            $this->_setError("Association failed: " . $this->getError());
            return false;
        }
        if (!$this->_getAssociation(
                $server,
                $handle,
                $macFunc,
                $secret,
                $expires)) {
            /* Use dumb mode */
            unset($handle);
            unset($macFunc);
            unset($secret);
            unset($expires);
        }

        $params = array();
        if ($version >= 2.0) {
            $params['openid.ns'] = Zend_OpenId::NS_2_0;
        }

        $params['openid.mode'] = $immediate ?
            'checkid_immediate' : 'checkid_setup';

        $params['openid.identity'] = $id;

        $params['openid.claimed_id'] = $claimedId;

        if ($version <= 2.0) {
            if ($this->_session !== null) {
                $this->_session->identity = $id;
                $this->_session->claimed_id = $claimedId;

                if ($server == 'https://www.google.com/accounts/o8/ud') {
                  $this->_session->identity = 'http://specs.openid.net/auth/2.0/identifier_select';
                  $this->_session->claimed_id = 'http://specs.openid.net/auth/2.0/identifier_select';
                }
            } else if (defined('SID')) {
                $_SESSION["zend_openid"] = array(
                    "identity" => $id,
                    "claimed_id" => $claimedId);

                if ($server == 'https://www.google.com/accounts/o8/ud') {
                  $_SESSION['zend_openid']['identity'] = 'http://specs.openid.net/auth/2.0/identifier_select';
                  $_SESSION['zend_openid']['claimed_id'] = 'http://specs.openid.net/auth/2.0/identifier_select';
                }
            } else {
                require_once "Zend/Session/Namespace.php";
                $this->_session = new Zend_Session_Namespace("zend_openid");
                $this->_session->identity = $id;
                $this->_session->claimed_id = $claimedId;

                if ($server == 'https://www.google.com/accounts/o8/ud') {
                  $params['openid.identity'] = 'http://specs.openid.net/auth/2.0/identifier_select';
                  $params['openid.claimed_id'] = 'http://specs.openid.net/auth/2.0/identifier_select';
                }
            }
        }

        if (isset($handle)) {
            $params['openid.assoc_handle'] = $handle;
        }

        $params['openid.return_to'] = Zend_OpenId::absoluteUrl($returnTo);

        if (empty($root)) {
            $root = Zend_OpenId::selfUrl();
            if ($root[strlen($root)-1] != '/') {
                $root = dirname($root);
            }
        }
        if ($version >= 2.0) {
            $params['openid.realm'] = $root;
        } else {
            $params['openid.trust_root'] = $root;
        }

        if (!Zend_OpenId_Extension::forAll($extensions, 'prepareRequest', $params)) {
            $this->_setError("Extension::prepareRequest failure");
            return false;
        }
        Zend_OpenId::redirect($server, $params, $response);
        return true;
    }
}
