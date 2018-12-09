<?php
if(!defined('ROOT')) exit('No direct script access allowed');

if(!defined("AUTH0_DOMAIN")) {
  exit("Auth0 configuration not found for this site");
}

require_once __DIR__ . '/vendor/autoload.php';

use Auth0\SDK\Auth0;

$auth0 = new Auth0([
  'domain' => AUTH0_DOMAIN,
  'client_id' => AUTH0_CLIENTID,
  'client_secret' => AUTH0_SECRET,
  'redirect_uri' => AUTH0_REDIRECT_URI,
  'audience' => AUTH0_AUDIENCE,
  'scope' => 'openid profile',
  'persist_id_token' => true,
  'persist_access_token' => true,
  'persist_refresh_token' => true,
//   'store' => false
]);

$userInfo = $auth0->getUser();

if (!$userInfo) {
  $auth0->login();
} else {
  printArray($userInfo);
}
?>