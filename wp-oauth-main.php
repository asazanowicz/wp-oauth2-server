<?php
/**
 * WordPress OAuth Server Main Class
 * Responsible for being the main handler
 *
 * @author Justin Greer <justin@justin-greer.com>
 * @package WordPress OAuth Server
 */

defined( 'ABSPATH' ) or die( 'No script kiddies please!' );

class WO_Server {

	/** Plugin Version */
	public $version = "1.0";

	/** Server Instance */
	public static $_instance = null;

	/** Default Settings */
	protected $defualt_settings = array(
		"enabled" => 1,
		"client_id_length" => 30,
		"require_exact_redirect_uri" => 0,
		"enforce_state" => 0,
		"refresh_token_lifetime" => 864000, // 10 Days
		"access_token_lifetime"	=> 86400, // 24 Hours
		"id_lifetime" => 3600  
	);

	function __construct() {

		if ( ! defined( 'WOABSPATH' ) ) {
			define( 'WOABSPATH', dirname( __FILE__ ) );
		}

		if ( ! defined( 'WOURI' ) ) {
			define( 'WOURI', plugins_url( '/', __FILE__) );
		}

		if ( function_exists( '__autoload' ) ) {
			spl_autoload_register( '__autoload' );
		}
		spl_autoload_register( array( $this, 'autoload') );

		add_filter( 'rest_authentication_errors', array( $this, 'wpoauth_block_unauthenticated_rest_requests' ) );
		add_filter( 'determine_current_user', array($this, '_wo_authenicate_bypass'), 21);
	}

	/**
	 * Bock unathenticated REST requests
	 *
	 * @since 3.4.6
	 */
	public function wpoauth_block_unauthenticated_rest_requests( $result ) {
		if ( ! is_user_logged_in() ) {
			return new WP_Error( 'rest_not_authorized', 'Authorization is required.', array( 'status' => 401 ) );
		}

		return $result;
	}

	/**
	 * Awesomeness for 3rd party support
	 * 
	 * Filter; determine_current_user
	 * Other Filter: check_authentication
	 *
	 * This creates a hook in the determine_current_user filter that can check for a valid access_token 
	 * and user services like WP JSON API and WP REST API.
	 * @param  [type] $user_id User ID to
	 *
	 * @author Mauro Constantinescu Modified slightly but still a contribution to the project.
	 */
	public function _wo_authenicate_bypass( $user_id ) {
		if ( $user_id && $user_id > 0 ) 
			return (int) $user_id;

		$o = get_option( 'wo_options' );
		if ( $o['enabled'] == 0 ) 
		return (int) $user_id;
		
		require_once( dirname( WPOAUTH_FILE ) . '/library/OAuth2/Autoloader.php');
		OAuth2\Autoloader::register();
		$server = new OAuth2\Server( new OAuth2\Storage\Wordpressdb() );
		$request = OAuth2\Request::createFromGlobals();
		if ( $server->verifyResourceRequest( $request ) ) {
			$token = $server->getAccessTokenData( $request );
			if ( isset( $token['user_id'] ) && $token['user_id'] > 0 ) {
				return (int) $token['user_id'];	
			}elseif( isset( $token['user_id'] ) && $token['user_id'] === 0 ) {

			}
		}
		return false;
	}

	/**
	 * populate the instance if the plugin for extendability
	 * @return object plugin instance
	 */
	public static function instance() {
		if ( is_null( self::$_instance ) ) {
			self::$_instance = new self();
		}

		return self::$_instance;
	}

	/**
	 * setup plugin class autoload
	 * @return void
	 */
	public function autoload( $class ) {
		$path = null;
		$class = strtolower( $class );
		$file = 'class-' . str_replace( '_', '-', $class ) . '.php';

		if ( strpos( $class, "wo_" ) === 0 ) {
			$path = dirname( __FILE__ ) . '/library/' . trailingslashit( substr( str_replace( '_', '-', $class ), 18 ) );
		}

		if ( $path && is_readable( $path . $file ) ) {
			include_once $path . $file;
			return;
		}
	}

	/**
	 * plugin setup. this is only ran on activation
	 * @return [type] [description]
	 */
	public function setup() {
		$options = get_option( "wo_options" );
		if (! isset( $options["enabled"] ) ) {
			update_option( "wo_options", $this->defualt_settings );
		}
		$this->install();
	}

	/**
	 * plugin update check
	 * @return [type] [description]
	 */
	public function install() {
		
		/** Install the required tables in the database */
		global $wpdb;

		$charset_collate = '';

		/** Set charset to current wp option */
		if (!empty($wpdb->charset)) {
			$charset_collate = "DEFAULT CHARACTER SET {$wpdb->charset}";
		}

		/** Set collate to current wp option */
		if (!empty($wpdb->collate)) {
			$charset_collate .= " COLLATE {$wpdb->collate}";
		}

		/** Update the version in the database */
		update_option("wpoauth_version", $this->version);

		$sql1 = "
			CREATE TABLE IF NOT EXISTS {$wpdb->prefix}oauth_clients (
        client_id             VARCHAR(80)   NOT NULL,
        client_secret         VARCHAR(80)   NOT NULL,
        redirect_uri          VARCHAR(2000),
        grant_types           VARCHAR(80),
        scope                 VARCHAR(4000),
        user_id               VARCHAR(80),
        name                  VARCHAR(80),
        description           LONGTEXT,
        PRIMARY KEY (client_id)
      );
			";

		$sql2 = "
			CREATE TABLE IF NOT EXISTS {$wpdb->prefix}oauth_access_tokens (
				id									 INT 						NOT NULL AUTO_INCREMENT,
				access_token         VARCHAR(4000) 	NOT NULL,
        client_id            VARCHAR(80)    NOT NULL,
        user_id              VARCHAR(80),
        expires              TIMESTAMP      NOT NULL,
        scope                VARCHAR(4000),
        PRIMARY KEY (id)
      );
			";

		$sql3 = "
			CREATE TABLE IF NOT EXISTS {$wpdb->prefix}oauth_refresh_tokens (
				refresh_token       VARCHAR(191)    NOT NULL,
        client_id           VARCHAR(191)    NOT NULL,
        user_id             VARCHAR(80),
        expires             TIMESTAMP      NOT NULL,
        scope               VARCHAR(4000),
        PRIMARY KEY (refresh_token)
      );
			";

		$sql4 = "
			CREATE TABLE IF NOT EXISTS {$wpdb->prefix}oauth_authorization_codes (
        authorization_code  VARCHAR(40)    NOT NULL,
        client_id           VARCHAR(191)    NOT NULL,
        user_id             VARCHAR(80),
        redirect_uri        VARCHAR(2000),
        expires             TIMESTAMP      NOT NULL,
        scope               VARCHAR(4000),
        id_token            VARCHAR(3000),
        PRIMARY KEY (authorization_code)
      );
			";

		$sql5 = "
			CREATE TABLE IF NOT EXISTS {$wpdb->prefix}oauth_scopes (
        scope               VARCHAR(80)  NOT NULL,
        is_default          BOOLEAN,
        PRIMARY KEY (scope)
      );
			";

		$sql6 = "
			CREATE TABLE IF NOT EXISTS {$wpdb->prefix}oauth_jwt (
        client_id           VARCHAR(191)   NOT NULL,
        subject             VARCHAR(80),
        public_key          VARCHAR(2000) NOT NULL,
        PRIMARY KEY (client_id)
      );
			";

		$sql7 = "
			CREATE TABLE IF NOT EXISTS {$wpdb->prefix}oauth_public_keys (
        client_id            VARCHAR(191),
        public_key           VARCHAR(2000),
        private_key          VARCHAR(2000),
        encryption_algorithm VARCHAR(100) DEFAULT 'RS256',
        PRIMARY KEY (client_id)
      );
			";

		include_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta($sql1);
		dbDelta($sql2);
		dbDelta($sql3);
		dbDelta($sql4);
		dbDelta($sql5);
		dbDelta($sql6);
		dbDelta($sql7);
	}
}

function _WO() {
	return WO_Server::instance();
}
$GLOBAL['WO'] = _WO();