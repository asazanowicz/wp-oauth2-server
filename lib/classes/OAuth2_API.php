<?php
/**
 * Front end hook for OAuth2 Provider for WordPress
 * 
 * @author Justin Greer
 */
global $wp_query;

/**
* Require OAuth Storage
*/
require_once( dirname(__FILE__) . '/admin/IOAuth2Storage.php' );

/**
* @var Set the object
*/
$oauth = new OAuth2(new IOAuth2StorageWP());

/**
* @var Clean the method from the query up a bit if needed
*/
$method = $wp_query->get('oauth');
$allowed = array(
				'authorize', 		// Authorize a user
				'request_token',	// Request a Token
				'request_access',	// Request Access
				'refresh_token',	// Refresh Token
				'login'				// This is for the authorization login screen
				);
				
	
/**
 * Check to make sure only parameters defined are used and nothing else
 */				
if (!in_array($method,$allowed)){
	header("Content-Type: application/json");
	header("Cache-Control: no-store");
	$error = json_encode(array('error' => 'Paramter method', 'error_description' => 'The method parameter is required and seems to be missing'));
	echo $error;
	exit;
	}
	
/**
* Check and run the right method based on the method passed in the query
*/
switch($method){
	
	case 'authorize':
	
		header('X-Frame-Options: DENY');
		error_reporting(0);
		
		if (!isset($_GET['client_id']) || empty($_GET['client_id'])){
			header("Content-Type: application/json");
			header("Cache-Control: no-store");
			$error = json_encode(array('error' => 'Parameter client_id', 'error_description' => 'The client_id parameter is required and seems to be missing'));
			echo $error;
			exit;
			}

		if(!isset($_GET['state']) || empty($_GET['state'])){
			header("Content-Type: application/json");
			header("Cache-Control: no-store");
			$error = json_encode(array('error' => 'Parameter state', 'error_description' => 'The state parameter is required and seems to be missing'));
			echo $error;
			exit;
			}
		
		if ( !is_user_logged_in() ) {
			wp_redirect( site_url() . '/membership-login/?sso_redirect='.$_GET['client_id'].'&state='.$_GET['state']);
			exit();
		}
		
		/**
		* @var Get the current user
		*/
		$current_user = wp_get_current_user();
		
		/**
		* @var Set the current users ID
		*/
		$userId = $current_user->ID;
		
		// @todo Not too sure what this is doing but we need to look at it.
		if($userId != ''){
			$oauth->finishClientAuthorization(TRUE, $userId, $_GET); // AUTO AUTHORIZE
		}
		
		try {
			$auth_params = $oauth->getAuthorizeParams();
		} catch (OAuth2ServerException $oauthError) {
			$oauthError->sendHttpResponse();
		}
	
		break;
	
	case 'request_token':
	
		header('X-Frame-Options: DENY');
		error_reporting(0);

		try {
			$oauth->grantAccessToken();
		} catch (OAuth2ServerException $oauthError) {
			$oauthError->sendHttpResponse();
		}
		
		break;
	
	case 'request_access':
	
	error_reporting(0);
	
	try {
		$token = $oauth->getBearerToken();
		$data = $oauth->verifyAccessToken($token);
		
		// GET THE USER ID FROM THE TOKEN AND NOT THE REQUESTING PARTY
		$user_id = $data['user_id'];
		
		global $wpdb;
		$info = $wpdb->get_row("SELECT * FROM {$wpdb->prefix}users WHERE ID = ".$user_id."");

		// don't send sensitive info accross the wire.
		unset($info->user_pass);
		unset($info->user_activation_key);

		header('Cache-Control: no-cache, must-revalidate');
		header('Content-type: application/json');
		print_r(json_encode($info));
		
	} catch (OAuth2ServerException $oauthError) {
		$oauthError->sendHttpResponse();
	}
	
	break;
	// RETURN EVERYTHING ABOUT THE CURRENT USER
	
	case 'refresh_token':
		header('Cache-Control: no-cache, must-revalidate');
		header('Content-type: application/json');
		print_r(json_encode(array('status'=>'Good')));
		break;
		
}// END SWITCH OF METHOD
?>