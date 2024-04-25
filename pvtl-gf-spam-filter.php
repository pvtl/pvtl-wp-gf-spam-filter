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

// Mark Entry as Spam
add_filter( 'gform_entry_is_spam', 'filter_gform_entry_is_spam_urls', 11, 3 );
function filter_gform_entry_is_spam_urls( $is_spam, $form, $entry ) {
    if ( $is_spam ) {
        return $is_spam;
    }
 
    $field_types_to_check = array(
        'hidden',
        'text',
        'textarea',
    );
 
    foreach ( $form['fields'] as $field ) {
        // Skipping fields which are administrative or the wrong type.
        if ( $field->is_administrative() || ! in_array( $field->get_input_type(), $field_types_to_check ) ) {
            continue;
        }
 
        // Skipping fields which don't have a value.
        $value = $field->get_value_export( $entry );
        if ( empty( $value ) ) {
            continue;
        }
 
        // If value contains a URL mark submission as spam.
        if ( preg_match( '~(https?|ftp):\/\/\S+~', $value ) ) {
            return true;
        }
    }
 
    return false;
}

//IP Rate Limit
add_filter( 'gform_entry_is_spam', 'filter_gform_entry_is_spam_ip_rate_limit', 11, 3 );
function filter_gform_entry_is_spam_ip_rate_limit( $is_spam, $form, $entry ) {
    if ( $is_spam ) {
        return $is_spam;
    }
 
    $ip_address = empty( $entry['ip'] ) ? GFFormsModel::get_ip() : $entry['ip'];
 
    if ( ! filter_var( $ip_address, FILTER_VALIDATE_IP ) ) {
        return true;
    }
 
    $key   = wp_hash( __FUNCTION__ . $ip_address );
    $count = (int) get_transient( $key );
 
    if ( $count >= 2 ) {
        return true;
    }
 
    $count ++;
    set_transient( $key, $count, HOUR_IN_SECONDS );
 
    return false;
}

//Mark a submission as spam if the first and last name inputs contain the same value
add_filter( 'gform_entry_is_spam', 'filter_gform_entry_is_spam_name_values', 11, 3 );
function filter_gform_entry_is_spam_name_values( $is_spam, $form, $entry ) {
    if ( $is_spam ) {
        return $is_spam;
    }
 
    foreach ( $form['fields'] as $field ) {
        // Skipping fields which are administrative or the wrong type.
        if ( $field->is_administrative() || $field->get_input_type() !== 'name' || $field->nameFormat === 'simple' ) {
            continue;
        }
 
        $first_name = rgar( $entry, $field->id . '.3' );
        $last_name  = rgar( $entry, $field->id . '.6' );
 
        if ( ! empty( $first_name ) && ! empty( $last_name ) && $first_name === $last_name ) {
            return true;
        }
    }
 
    return false;
}

//Detect English Language API
add_filter( 'gform_entry_is_spam', 'filter_gform_entry_is_spam_detectlanguage', 11, 3 );
function filter_gform_entry_is_spam_detectlanguage( $is_spam, $form, $entry ) {
    if ( $is_spam ) {
        return $is_spam;
    }
 
    $field_types_to_check = array(
        'text',
        'textarea',
    );
 
    $text_to_check = array();
 
    foreach ( $form['fields'] as $field ) {
        // Skipping fields which are administrative or the wrong type.
        if ( $field->is_administrative() || ! in_array( $field->get_input_type(), $field_types_to_check ) ) {
            continue;
        }
 
        // Skipping fields which don't have a value.
        $value = $field->get_value_export( $entry );
        if ( empty( $value ) ) {
            continue;
        }
 
        $text_to_check[] = $value;
    }
 
    if ( empty( $text_to_check ) ) {
        return false;
    }
 
    $response = wp_remote_post( 'https://ws.detectlanguage.com/0.2/detect', array(
        'headers' => array(
            'Authorization' => '99e02d95abbdec8143661410e20bf7e4',
            'Content-Type'  => 'application/json',
        ),
        'body'    => json_encode( array( 'q' => $text_to_check ) ),
    ) );
 
    if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) {
        GFCommon::log_debug( __METHOD__ . '(): $response => ' . print_r( $response, true ) );
 
        return false;
    }
 
    $body = json_decode( wp_remote_retrieve_body( $response ), true );
    GFCommon::log_debug( __METHOD__ . '(): $body => ' . print_r( $body, true ) );
 
    if ( empty( $body['data'] ) || empty( $body['data']['detections'] ) || ! is_array( $body['data']['detections'] ) ) {
        return false;
    }
 
    foreach ( $body['data']['detections'] as $detections ) {
        foreach ( $detections as $detection ) {
            // Not spam if language is English.
            if ( rgar( $detection, 'language' ) === 'en' && rgar( $detection, 'isReliable' ) ) {
                return false;
            }
        }
    }
 
    return true;
}

// Add Australian address filter
add_filter( 'gform_address_types', 'australian_address_type' );
function australian_address_type( $address_types ) {
    $address_types['australia'] = array(
        'label'       => 'Australian',
        'country'     => 'Australia',
        'zip_label'   => 'Postcode',
        'state_label' => 'State',
        'states'      => array(
            'ACT' => 'Australian Capital Territory',
            'NT'  => 'Northern Territory',
            'NSW' => 'New South Wales',
            'QLD' => 'Queensland',
            'SA'  => 'South Australia',
            'TAS' => 'Tasmania',
            'VIC' => 'Victoria',
            'WA'  => 'Western Australia',
        )
    );
 
    return $address_types;
}