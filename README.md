
# OAuth2 For WordPress

Your site will be able to provide Single Sign On and also deliver authorized user data using the OAuth 2.0 API.

Contributors: Justin Greer, Joel Wickard, Neil Pullman, Andriej Sazanowicz

Requires at least: 3.4.2  
Tested on: 6.2.2  
License: GPLv2 or later  

License URI: http://www.gnu.org/licenses/gpl-2.0.html

## Description

ENSURE THAT WP_DEBUG IS SET TO FALSE IN THE WP-CONFIG.PHP FILE..... NO JOKE!!!!

OAuth2 Complete is a ONE OF A KIND plugin that instantly turns your WordPress webste into a valid OAuth v2 provider. The plugin is built using OAuth2 Draft 20 standards. The backend is designed to be extremely easy to use for any level of experience. OAuth is a great tool but leaves most developers behind since it a bit technical.
The plugin has aleady done the hard part for you.

Current Features Features:

*   Allows for Single Sign On abilities
*   Backend panel for adding apps/clients
*	3 methods built-in to allow for a plug-and-play system

## Installation

1. Upload `wordpress-oauth` to the `/wp-content/plugins/` directory or use the built-in plugin install system
1. Activate the plugin through the 'Plugins' menu in WordPress
1. Click 'Settings' and then 'Oermalinks'. Then simply click 'Save Changes' to flush the rewrite rules.
1. You're Ready to Rock

## Frequently Asked Questions

### How do I add an app/client?

Visit the OAuth2 Complete dashboard by clicking `Provider` in the WordPress admin panel. Once you are in the dashboard, there is a form labeled `Add Client`. Give your client a name and a redirect URI. The redirect URI is the HTTP location where the user will be returned to after authenticating (your client should provide this for you). Click `Add Client` and your client will be added to your Consumer Manager table.

### How does a client connect to my website to use the Single Sign On?

Currently there is 3 Methods that OAuth2 Provider has built in:

1. http://example.com/oauth/authorize

1. http://example.com/oauth/request_token

1. http://example.com/oauth/request_access

Authorize requires only 3 parameters:

* client_id
* response_type - Supported value's = `code`
* state
* Example call `http://example.com/oauth/authorize?client_id=the_client_id&state=anything_you_want&response_type=code`

Request Token Requires only 4 parameters

* code - This is auth code returned from the authorize call
* grant_type - Supported value's = `authorization_code`
* client_id
* client_secret
* Example call `http://example.com/oauth/request_token?code=the_auth_key_sent_back_from_the_authorize_call&grant_type=authorization_code&client_id=the_client_id&client_secret=the_client_secret`

Request Access Requires only 1 parmeter

* access_token - This is the access_token provided from the Request Token call
* Example Call `http://example.com/oauth/request_access?access_token=the_token_from_the_request_call`

### Extended to support Wordpress role claim. 
```
{
    "ID": "1",
    "user_login": "just.user",
    "user_nicename": "just-user",
    "user_email": "just.user@example.com",
    "user_url": "",
    "user_registered": "2023-03-20 14:21:42",
    "user_status": "0",
    "display_name": "just.user",
    "role": [
        "free"
    ]
}
```

NOTE: All returns will be in JSON format.
