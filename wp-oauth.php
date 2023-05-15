<?php

defined( 'ABSPATH' ) or die( 'No script kiddies please!' );

if (! defined( 'WPOAUTH_FILE' ) ) {
	define( 'WPOAUTH_FILE', __FILE__ );
}

/** 
 * 5.4 Strict Mode Temp Patch
 *
 * Since PHP 5.4, WP will through notices due to the way WP calls statically
 */
// function _wo_server_register_files() {
// 	wp_register_style( 'wo_admin', plugins_url( '/assets/css/admin.css', __FILE__ ) );
// 	wp_register_script( 'wo_admin', plugins_url( '/assets/js/admin.js', __FILE__ ) );
// }
// add_action( 'wp_loaded', '_wo_server_register_files' );

require_once( dirname(__FILE__) . '/wp-oauth-main.php' );

/**
 * Adds/registers query vars
 * @return void
 */
function _wo_server_register_query_vars() {
	_wo_server_register_rewrites();

	global $wp;
	$wp->add_query_var( 'oauth' );
	//$wp->add_query_var( 'well-known' );
	//$wp->add_query_var( 'wpoauthincludes' );
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
	//add_rewrite_rule( '^.well-known/(.+)','index.php?well-known=$matches[1]','top' );
	//add_rewrite_rule( '^wpoauthincludes/(.+)','index.php?wpoauthincludes=$matches[1]','top' );
}


