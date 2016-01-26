<?php

namespace EightPoints\Guzzle\Plugin;

use       GuzzleHttp\Event\BeforeEvent,
          GuzzleHttp\Event\SubscriberInterface;

/**
 * Adds WSSE auth headers based on http://www.xml.com/pub/a/2003/12/17/dive.html
 *
 * @package   EightPoints\Guzzle\Plugin
 *
 * @copyright 8points IT
 * @author    Florian Preusner
 *
 * @version   2.0
 * @since     2013-10
 */
class WsseAuthPlugin implements SubscriberInterface {

    /**
     * @var string $username
     */
    private $username;

    /**
     * @var string $password
     */
    private $password;

    /**
     * Constructor
     *
     * @author  Florian Preusner
     * @version 1.0
     * @since   2013-10
     *
     * @param   string $username
     * @param   string $password
     */
    public function __construct($username, $password) {
        $this->setUsername( $username);
        $this->setPassword( $password);
    } // end: __construct()

    /**
     * Get Username
     *
     * @author  Florian Preusner
     * @version 1.0
     * @since   2013-10
     *
     * @return  string $username
     */
    public function getUsername() {

        return $this->username;
    } // end: getUsername()

    /**
     * Set Username
     *
     * @author  Florian Preusner
     * @version 1.0
     * @since   2013-10
     *
     * @param   string $value
     * @return  void
     */
    public function setUsername($value) {

        $this->username = $value;
    } // end: setUsername()

    /**
     * Get Password
     *
     * @author  Florian Preusner
     * @version 1.0
     * @since   2013-10
     *
     * @return  string $password
     */
    public function getPassword() {

        return $this->password;
    } // end: getPassword()

    /**
     * Set Password
     *
     * @author  Florian Preusner
     * @version 1.0
     * @since   2013-10
     *
     * @param   string $value
     * @return  void
     */
    public function setPassword($value) {

        $this->password = $value;
    } // end: setPassword()

    /**
     * {@inheritdoc}
     *
     * @author  Florian Preusner
     * @version 2.0
     * @since   2013-10
     */
    public function getEvents() {

        return ['before' => ['onBefore']];
    } // end: getEvents

    /**
     * Add WSSE auth headers to Request
     *
     * @author  Florian Preusner
     * @version 2.0
     * @since   2013-10
     *
     * @param   BeforeEvent $event
     *
     * @return  void
     */
    public function onBefore(BeforeEvent $event) {
        $createdAt = date('c');
        $nonce = $this->generateNonce();
        $digest = $this->generateDigest($nonce, $createdAt, $this->password);

        $request = $event->getRequest();
        $xwsse   = array(
            sprintf('Username="%s"', $this->username),
            sprintf('PasswordDigest="%s"', $digest),
            sprintf('Nonce="%s"', $nonce),
            sprintf('Created="%s"', $createdAt)
        );

        $request->addHeader('Authorization', 'WSSE profile="UsernameToken"');
        $request->addHeader('X-WSSE', sprintf('UsernameToken %s', implode(', ', $xwsse)));
    } // end: onBefore()

    /**
     * Generate Digest
     *
     * @author  Florian Preusner
     * @version 1.0
     * @since   2013-10
     *
     * @param   string $nonce
     * @param   string $createdAt
     * @param   string $password
     *
     * @return  string
     */
    public function generateDigest($nonce, $createdAt, $password) {

        return base64_encode(sha1(base64_decode($nonce) . $createdAt . $password, true));
    } // end: generateDigest()

    /**
     * Generate Nonce (number user once)
     *
     * @author  Florian Preusner
     * @version 1.0
     * @since   2013-10
     *
     * @return  string
     */
    public function generateNonce() {

        return hash('sha512', uniqid(true));
    } // end: generateNonce()
} // end: WsseAuthPlugin