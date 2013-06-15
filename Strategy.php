<?php

/**
 * LinkedIn strategy for Opauth
 * based on https://developer.linkedin.com/documents/authentication
 *
 * More information on Opauth: http://opauth.org
 *
 * @copyright    Copyright © U-Zyn Chua (http://uzyn.com)
 * @link         http://opauth.org
 * @package      Opauth.LinkedInStrategy
 * @license      MIT License
 */

namespace Opauth\Strategy\LinkedIn;

use Opauth\AbstractStrategy;

/**
 * LinkedIn strategy for Opauth
 * based on https://developer.linkedin.com/documents/authentication
 *
 * @package			Opauth.LinkedIn
 */
class Strategy extends \Opauth\Strategy\OAuth2\Strategy {

	/**
	 * Compulsory config keys, listed as unassociative arrays
	 */
	public $expects = array('api_key', 'secret_key');

	/**
	 * Optional config keys, without predefining any default values.
	 */
	public $optionals = array('scope', 'state', 'response_type', 'profile_fields');

	/**
	 * Optional config keys with respective default values, listed as associative arrays
	 * eg. array('scope' => 'email');
	 */
	public $defaults = array(
		'response_type' => 'code',
		'state' => 'opauth-linkedin',
		'profile_fields' => array('id', 'first-name', 'last-name', 'maiden-name', 'formatted-name', 'headline', 'industry', 'summary', 'email-address', 'picture-url', 'location:(name)', 'public-profile-url', 'site-standard-profile-request')
	);

	public $responseMap = array(
		'name' => 'formatted-name',
		'uid' => 'id',
		'info.name' => 'formatted-name',
		'info.first_name' => 'first-name',
		'info.last_name' => 'last-name',
		'info.email' => 'email-address',
		'info.headline' => 'headline',
		'info.description' => 'summary',
		'info.location' => 'location.name',
		'info.image' => 'picture-url',
		'info.urls.linkedin' => 'public_profile-url',
		'info.urls.linkedin_authenticated' => 'site-standard-profile-request.url'
	);

	protected $requestUrl = 'https://www.linkedin.com/uas/oauth2/authorization';

	protected $requestParams = array('api_key' => 'client_id', 'state', 'response_type', 'scope');

	protected $tokenUrl = 'https://www.linkedin.com/uas/oauth2/accessToken';

	protected $userUrl = null;

	protected function callbackParams() {
		$params = array('grant_type' => 'authorization_code');

		return $this->addParams(array(
			'api_key' => 'client_id',
			'secret_key' => 'client_secret'
		), $params);
	}

	protected function accessToken($code) {
		return json_decode($this->postToken($code));
	}

	/**
	 * Overrides OAuth2's getUser()
	 */
	protected function getUser($access_token) {
		if (empty($this->userUrl)) {
			if (is_array($this->strategy['profile_fields'])) {
				$fields = '(' . implode(',', $this->strategy['profile_fields']) . ')';
			} else {
				$fields = '(' . $this->strategy['profile_fields'] . ')';
			}

			$this->userUrl = 'https://api.linkedin.com/v1/people/~:' . $fields;
		}

		$user = $this->http->get($this->userUrl, array('oauth2_access_token' => $access_token));
		return $this->recursiveGetObjectVars(simplexml_load_string($user));
	}

	protected function callbackResponse($response, $results) {
		$response->credentials = array(
			'token' => $results['access_token'],
			'expires' => date('c', time() + $results['expires_in'])
		);

		return $response;
	}
}
