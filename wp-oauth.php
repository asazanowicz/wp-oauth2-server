<?php
/**
 * Plugin Name: CyberTechTalk OAuth Server
 * Plugin URI: http://www.techtalk.andriejsazanowicz.com/
 * Version: 1.0.0
 * Description: Full OAuth2 Server for WordPress. User Authorization Management Systems For WordPress.
 * Author: Andriej Sazanowicz
 * Author URI: http://www.techtalk.andriejsazanowicz.com/
 * Text Domain: cybertechtalk
 *
 * @author  Justin Greer <justin@justin-greer.com>
 * @package WP OAuth Server
 */

defined( 'ABSPATH' ) or die( 'No script kiddies please!' );

if ( ! defined( 'WPOAUTH_FILE' ) ) {
	define( 'WPOAUTH_FILE', __FILE__ );
}

if ( ! defined( 'WPOAUTH_VERSION' ) ) {
	define( 'WPOAUTH_VERSION', '1.0.0' );
}

require_once dirname( __FILE__ ) . '/includes/functions.php';
require_once dirname( __FILE__ ) . '/wp-oauth-main.php';

/**
 * Adds/registers query vars
 *
 * @return void
 */
function wpoauth_server_register_query_vars() {
	_wo_server_register_rewrites();
	
	global $wp;
	$wp->add_query_var( 'oauth' );
	$wp->add_query_var( 'well-known' );
	$wp->add_query_var( 'wpoauthincludes' );
}

add_action( 'init', 'wpoauth_server_register_query_vars' );

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
	add_rewrite_rule( '^oauth/(.+)', 'index.php?oauth=$matches[1]', 'top' );
	add_rewrite_rule( '^.well-known/(.+)', 'index.php?well-known=$matches[1]', 'top' );
	add_rewrite_rule( '^wpoauthincludes/(.+)', 'index.php?wpoauthincludes=$matches[1]', 'top' );
}

/**
 * [template_redirect_intercept description]
 *
 * @return [type] [description]
 */
function wpoauth_server_template_redirect_intercept( $template ) {
	global $wp_query;
	
	if ( $wp_query->get( 'oauth' ) || $wp_query->get( 'well-known' ) ) {
		define( 'DOING_OAUTH', true );
		include_once dirname( __FILE__ ) . '/library/class-wo-api.php';
		exit;
	}
	
	return $template;
}

add_filter( 'template_include', 'wpoauth_server_template_redirect_intercept', 100 );

/**
 * OAuth2 Server Activation
 *
 * @param [type] $network_wide [description]
 *
 * @return [type]               [description]
 */
function wpoauth_server_activation( $network_wide ) {
	if ( function_exists( 'is_multisite' ) && is_multisite() && $network_wide ) {
		$mu_blogs = wp_get_sites();
		foreach ( $mu_blogs as $mu_blog ) {
			switch_to_blog( $mu_blog['blog_id'] );
			_wo_server_register_rewrites();
			flush_rewrite_rules();
		}
		restore_current_blog();
	} else {
		_wo_server_register_rewrites();
		flush_rewrite_rules();
	}
	
	// Schedule the cleanup workers
	wp_schedule_event( time(), 'hourly', 'wpo_global_cleanup' );
}

register_activation_hook( __FILE__, 'wpoauth_server_activation' );

/**
 * OAuth Server Deactivation
 *
 * @param [type] $network_wide [description]
 *
 * @return [type]               [description]
 */
function wpoauth_server_deactivation( $network_wide ) {
	if ( function_exists( 'is_multisite' ) && is_multisite() && $network_wide ) {
		$mu_blogs = wp_get_sites();
		foreach ( $mu_blogs as $mu_blog ) {
			switch_to_blog( $mu_blog['blog_id'] );
			flush_rewrite_rules();
		}
		restore_current_blog();
	} else {
		flush_rewrite_rules();
	}
	
	// Remove the cleanup workers.
	wp_clear_scheduled_hook( 'wpo_global_cleanup' );
}

register_deactivation_hook( __FILE__, 'wpoauth_server_deactivation' );

register_activation_hook( __FILE__, array( new WO_Server(), 'setup' ) );
