<?php

defined( 'ABSPATH' ) or die( 'No script kiddies please!' );

if (! defined( 'WPOAUTH_FILE' ) ) {
	define( 'WPOAUTH_FILE', __FILE__ );
}

require_once( dirname(__FILE__) . '/wp-oauth-main.php' );

/**
 * Adds/registers query vars
 * @return void
 */
function _wo_server_register_query_vars() {
	_wo_server_register_rewrites();

	global $wp;
	$wp->add_query_var( 'oauth' );
}
add_action( 'init', '_wo_server_register_query_vars' );

/**
 * Registers rewrites for OAuth2 Server
 * 
 * - authorize
 * - token
 * - .well-known
 * - wpoauthincludes
 * 
 * @return void
 */
function _wo_server_register_rewrites() {
	add_rewrite_rule( '^oauth/(.+)','index.php?oauth=$matches[1]','top' );
}


