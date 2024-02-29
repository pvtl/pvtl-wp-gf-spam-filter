<?php
/**
 * Plugin Name: Gravity Forms Spam Filter
 * Plugin URI: https://www.pivotalagency.com.au/
 * Description: Places spam filters into Wordpress to only allow Australian mobile and landline numbers (04, 02, 03, 07, 08)
 * Author: Pivotal Agency
 * Author URI: https://www.pivotalagency.com.au/
 * Version: 1.0
 * Text Domain: pvtl-wp-gf-spam-filter
 * License: GPL3+
*/

// Gravity Forms - Phone REGEX AU Filter
add_filter( 'gform_phone_formats', 'au_phone_format' );
function au_phone_format( $phone_formats ) {
    $phone_formats['au'] = array(
        'label'       => 'Australia',
        'mask'        => '99 9999 9999',
        'regex'       => '/^\({0,1}((0|\+61)(2|4|3|7|8)){0,1}\){0,1}(\ |-){0,1}[0-9]{2}(\ |-){0,1}[0-9]{2}(\ |-){0,1}[0-9]{1}(\ |-){0,1}[0-9]{3}$/',
        'instruction' => 'Australian phone numbers.',
    );
 
    return $phone_formats;
}

// Gravity Forms Spam Filter - disallowing 555- numbers & numbers starting with "8"
if (!empty($phone_filter)) {
    if (
        ( strlen($phone_filter) == 11 && substr($phone_filter, 0, 1) == '8' ) ||
        strlen($phone_filter) <= 6 ||
        substr($phone_filter, 0, 4 ) === '555-'
    ) {
        // Spam block code here
    }
}