<?php
/*
Plugin Name: 3rd Party Authentication
Version: 0.1.3
Plugin URI: http://jameslow.com/2008/11/24/3rd-party-authentication/
Description: 3rd Party Authentication is a wordpress plugin that allows wordpress to authenticate against other authentication systems.
Author: James Low
Author URI: http://jameslow.com/
*/

require_once 'googleclientlogin.php';

if (! class_exists('ThirdPartyPlugin')) {
	abstract class ThirdPartyAuthenticator {
		abstract function authenticate($username, $password);
	}
	abstract class EmailAuthenticator extends ThirdPartyAuthenticator {
		function __construct ($server, $ssl = false, $port = null) {
			$this->server = $server;
			$this->ssl = $ssl;
			if (isset($port) && $port != '') {
				$this->port = $port;
			} else {
				$this->port = getDefaultPort();
			}
		}
		function getURL() {
			if ($this->ssl) {
				return 'ssl://'.$this->server;
			} else {
				return 'tcp://'.$this->server;
			}
		}
		abstract function getDefaultPort();
	}
	class IMAPAuthenticator extends EmailAuthenticator {
		function __construct ($server, $ssl = false, $port = null) {
			parent::__construct($server, $ssl, $port);
		}
		function getDefaultPort() {
			if($this->ssl) {
				return 993;
			} else {
				return 143;
			}
		}
		function authenticate($username, $password) {
			$ssl = fsockopen($this->getURL(), $this->port, $err, $errdata, 40);
			if ($ssl) {
				$auth = fgets($ssl, 256);
				fputs($ssl, '0000 CAPABILITY'."\n");
				$auth = fgets($ssl, 256);
				$auth = fgets($ssl, 256);
				fputs($ssl, '0001 LOGIN '.$username.' '.$password."\n");
				$auth = fgets($ssl, 256);
				fclose ($ssl);
				if(preg_match('/Success/',$auth) || preg_match('/Ok/',$auth)) {
					return true;
				} else {
					return false;
				}
			}
			return false;
		}
	}
	class POP3Authenticator extends EmailAuthenticator {
		function __construct ($server, $ssl = false, $port = null) {
			parent::__construct($server, $ssl, $port);
		}
		function getDefaultPort() {
			if($this->ssl) {
				return 992;
			} else {
				return 110;
			}
		}
		function authenticate($username, $password) {
			$ssl = fsockopen($this->getURL(), $this->port, $err, $errdata, 40);
			if ($ssl) {
				$auth = fgets($ssl, 256);
				fputs($ssl, 'USER '.$username."\n");
				$auth = fgets($ssl, 256);
				fputs($ssl, 'PASS '.$password."\n");
				$auth = fgets($ssl, 256);
				fclose ($ssl);
				if(preg_match('/OK/',$auth)) {
					return true;
				} else {
					return false;
				}
			}
			return false;
		}
	}
	class GoogleAuthenticator extends ThirdPartyAuthenticator {
		function authenticate($username, $password) {
			$google = new GoogleClientLogin();
			return $google->Authenticate($username,$password);
		}
	}
	
	class ThirdPartyPlugin {
		function ThirdPartyPlugin() {
			if (isset($_GET['activate']) and $_GET['activate'] == 'true') {
				add_action('init', array(&$this, 'initialize_options'));
			}
			add_action('admin_menu', array(&$this, 'add_options_page'));
			#add_action('wp_authenticate_user', array(&$this, 'authenticate'), 10, 2);
			add_filter('check_password', array(&$this, 'check_password'), 10, 4);
			#add_action('wp_logout', array(&$this, 'logout'));
			if (!(bool) get_option('3rd_party_allow_regular')) {
				add_action('lost_password', array(&$this, 'disable_function'));
				add_action('retrieve_password', array(&$this, 'disable_function'));
				add_action('password_reset', array(&$this, 'disable_function'));
				add_action('check_passwords', array(&$this, 'generate_password'), 10, 3);
				add_filter('show_password_fields', array(&$this, 'disable_password_fields'));
			}
		}


		/*************************************************************
		 * Plugin hooks
		 *************************************************************/

		/*
		 * Add options for this plugin to the database.
		 */
		function initialize_options() {
			if (current_user_can('manage_options')) {
				add_option('3rd_party_allow_regular', false, 'Allow regular logins as well as email logins?');
				add_option('3rd_party_google_apps_dont', false, "Don't authenticate gmail/googlemail logins?");
				add_option('3rd_party_google_apps_all', false, 'Authenticate all domains via google apps?');
				add_option('3rd_party_google_apps_domains', '', 'A comma seperated list of domains to authenticate via google apps.');
			}
		}

		/*
		 * Add an options pane for this plugin.
		 */
		function add_options_page() {
			if (function_exists('add_options_page')) {
				add_options_page('3rd Party Authentication', '3rd Party Authentication', 9, __FILE__, array(&$this, '_display_options_page'));
			}
		}
		
		function check_password($check, $password, $hash, $user_id) {
			if ($check && (bool) get_option('3rd_party_allow_regular')) {
				return true;
			} else {
				$user = get_userdata($user_id);
				$username = $user->user_login;
				$parts = explode("@",$username);
				if (count($parts) != 2) {
					die('Username not an email address.');
				}
				$useemail = false;
				$email_settings = get_option('3rd_party_email_settings');
				if (is_array($email_settings)) {
					foreach ($email_settings as $setting) {
						if (strtolower($setting['domain']) == strtolower($parts[1])) {
							$useemail = true;
							break;
						}
					}
				}
				if ($useemail) {
					$usessl = (bool) $setting['ssl'];
					if ((bool) $setting['imap'] == true) {
						$authenticator = new IMAPAuthenticator($setting['server'],$usessl,$setting['port']);
					} else {
						$authenticator = new POP3Authenticator($setting['server'],$usessl,$setting['port']);
					}
					if((bool) $setting['remove']) {
						$username = $parts[0];
					}
				} else {
					$usegoogle = false;
					$googleall = (bool) get_option('3rd_party_google_apps_all');
					if (!$googleall) {
						$googledomains = explode(",",ereg_replace(' ','',get_option('3rd_party_google_apps_domains')));
						if (!(bool) get_option('3rd_party_google_apps_dont')) {
							$googledomains[] = 'gmail.com';
							$googledomains[] = 'googlemail.com';
						}
						foreach ($googledomains as $domain) {
							if(strtolower($domain) == strtolower($parts[1])) {
								$usegoogle = true;
								break;
							}
						}
					} else {
						$usegoogle = true;
					}
					if ($usegoogle) {
						$authenticator = new GoogleAuthenticator();
					}
				}
				
				if (isset($authenticator)) {
					return $authenticator->authenticate($username,$password);
				} else {
					die('Domain '.$parts[1].' not supported.');
				}
			}
		}
		
		/*
		 * If the REMOTE_USER or REDIRECT_REMOTE_USER evironment
		 * variable is set, use it as the username. This assumes that
		 * you have externally authenticated the user.
		 */
		function authenticate($username, $password) {
			/*
			$google = new GoogleClientLogin();
			if ($username != '' && $google->Authenticate($username,$password)) {
				$user = get_userdatabylogin($username);
				if (! $user or $user->user_login != $username) {
					if ((bool) get_option('3rd_party_auto_create_user')) {
						$this->_create_user($username);
					}
					else {
						// Bail out to avoid showing the login form
						die("User $username does not exist in the WordPress database");
					}
				}
			} else {
				die("Username or password incorrect");
			}
			*/
		}


		/*
		 * Skip the password check, since we've externally authenticated.
		 */
		function skip_password_check($check, $password, $hash, $user_id) {
			return true;
		}

		/*
		 * Generate a password for the user. This plugin does not
		 * require the user to enter this value, but we want to set it
		 * to something nonobvious.
		 */
		function generate_password($username, $password1, $password2) {
			$password1 = $password2 = $this->_get_password();
		}

		/*
		 * Used to disable certain display elements, e.g. password
		 * fields on profile screen.
		 */
		function disable_password_fields($show_password_fields) {
			return false;
		}

		/*
		 * Used to disable certain login functions, e.g. retrieving a
		 * user's password.
		 */
		function disable_function() {
			die('Disabled');
		}


		/*************************************************************
		 * Functions
		 *************************************************************/

		/*
		 * Generate a random password.
		 */
		function _get_password($length = 10) {
			return substr(md5(uniqid(microtime())), 0, $length);
		}

		/*
		 * Display the options for this plugin.
		 */
		function _display_options_page() {
			$submit = $_REQUEST['Submit'];
			$new_email_settings;
			if (isset($submit)) {
				$domains = $_REQUEST['3rd_party_domain'];
				$servers = $_REQUEST['3rd_party_server'];
				$ports = $_REQUEST['3rd_party_port'];
				$imaps = $_REQUEST['3rd_party_imap'];
				$ssls = $_REQUEST['3rd_party_ssl'];
				$removes = $_REQUEST['3rd_party_remove'];
				$i=0;
				foreach($domains as $domain) {
					if ($domains[$i] != '') {
						$new_setting = array();
						$new_setting['domain'] = $domains[$i];
						$new_setting['server'] = $servers[$i];
						$new_setting['port'] = $ports[$i];
						$found = false;
						if (is_array($imaps)) {
							foreach ($imaps as $imap) {
								if ($imap == $domain) {
									$found = true;
									break;
								}
							}
						}
						$new_setting['imap'] = $found;
						$found = false;
						if (is_array($ssls)) {
							foreach ($ssls as $ssl) {
								if ($ssl == $domain) {
									$found = true;
									break;
								}
							}
						}
						$new_setting['ssl'] = $found;
						$found = false;
						if (is_array($removes)) {
							foreach ($removes as $remove) {
								if ($remove == $domain) {
									$found = true;
									break;
								}
							}
						}
						$new_setting['remove'] = $found;
						$new_email_settings[] = $new_setting;
					}
					$i++;
				}
				update_option('3rd_party_email_settings',$new_email_settings);
			}
			
			$allow_regular = (bool) get_option('3rd_party_allow_regular');
			$google_apps_dont = (bool) get_option('3rd_party_google_apps_dont');
			$google_apps_all = (bool) get_option('3rd_party_google_apps_all');
			$google_apps_domains = get_option('3rd_party_google_apps_domains');
			$email_settings = get_option('3rd_party_email_settings');
?>
<div class="wrap">
  <h2>3rd Party Authentication Options</h2>
  <form action="options.php" method="post">
    <input type="hidden" name="action" value="update" />
    <input type="hidden" name="page_options" value="3rd_party_allow_regular,3rd_party_google_apps_dont,3rd_party_google_apps_all,3rd_party_google_apps_domains" />
    <?php if (function_exists('wp_nonce_field')): wp_nonce_field('update-options'); endif; ?>

    <table class="form-table">
      <tr valign="top">
        <th scope="row"><label for="3rd_party_allow_regular">Allow regular logins?</label></th>
        <td>
          <input type="checkbox" name="3rd_party_allow_regular" id="3rd_party_allow_regular"<?php if ($allow_regular) echo ' checked="checked"' ?> value="1" />
          Allow regular logins as well as email/google logins?<br />
        </td>
      </tr>
      <tr valign="top">
        <th scope="row"><label for="3rd_party_google_apps_domains">Google apps settings</label></th>
        <td>
          <input type="checkbox" name="3rd_party_google_apps_dont" id="3rd_party_google_apps_dont"<?php if ($google_apps_dont) echo ' checked="checked"' ?> value="1" />Don't authenticate gmail.com/googlemail.com logins?
          <br /><input type="checkbox" name="3rd_party_google_apps_all" id="3rd_party_google_apps_all"<?php if ($google_apps_all) echo ' checked="checked"' ?> value="1" />Authenticate all domains not specified in email settings below, via google apps?
          <br /><input type="text" name="3rd_party_google_apps_domains" id="3rd_party_google_apps_domains" value="<?php echo htmlspecialchars($google_apps_domains) ?>" size="50" />
          A comma seperated list of domains to authenticate via google apps.
        </td>
      </tr>
    </table>
    <p class="submit">
      <input type="submit" name="Submit" value="Save Changes" />
    </p>
  </form>
  <h2>Email settings</h2>
  Set the domain as blank, then click "Save Email Settings" to delete a row. If you leave the port blank the default is used. If IMAP is left unchecked, server is assumed to be POP.
  If your email provider does not require you to enter a full username with the domain, check "Remove Domain".
	<form method="post" action="">
	<table>
	<tr><th>Domain</th><th>Server</th><th>Port</th><th>IMAP</th><th>Use SSL</th><th>Remove Domain</th></tr>
<?php 
	function echo_row($domain = "", $server = "", $port = "", $imap = false, $ssl = false, $remove = false) {
		echo '<tr>';
		echo '<td><input type="text" name="3rd_party_domain[]" value="'.$domain.'" size="20" /></td>';
		echo '<td><input type="text" name="3rd_party_server[]" value="'.$server.'" size="20" /></td>';
		echo '<td><input type="text" name="3rd_party_port[]" value="'.$port.'" size="5" /></td>';
		echo '<td><input type="checkbox" name="3rd_party_imap[]" '.($imap ? ' checked="checked"' : '' ).' value="'.$domain.'" /></td>';
		echo '<td><input type="checkbox" name="3rd_party_ssl[]" '.($ssl ? ' checked="checked"' : '' ).' value="'.$domain.'" /></td>';
		echo '<td><input type="checkbox" name="3rd_party_remove[]" '.($remove ? ' checked="checked"' : '' ).' value="'.$domain.'" /></td>';
		echo '</tr>';
	}
	echo_row();
	if (is_array($email_settings)) {
		foreach ($email_settings as $setting) {
			echo echo_row($setting['domain'],$setting['server'],$setting['port'],$setting['imap'],$setting['ssl'],$setting['remove']);
		}
	}
?>
	</table>
    <p class="submit">
	<input type="submit" name="Submit" value="Save Email Settings" />
	</p>
	</form>
</div>
<?php
		}
	}
}

// Load the plugin hooks, etc.
$third_party_plugin = new ThirdPartyPlugin();
?>
