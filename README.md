# Share Previews

A WordPress must-use plugin that enables secure, shareable preview links for draft posts and pages without requiring authentication.

**Version:** 1.0.0  
**Author:** ProVia Marketing Team  
**License:** GPL v2 or later  
**Location:** `/wp-content/mu-plugins/share-previews/`

---

## Overview

Share Previews allows content editors to generate secure, time-limited preview URLs for draft posts. These URLs can be shared with clients, stakeholders, or team members who don't have WordPress accounts, enabling them to review content before publication.

### Key Features

- 🔒 **Secure by Default** – Cryptographically random 64-character keys with timing-safe comparison
- 🛡️ **Rate Limiting** – 10 attempts per minute per IP to prevent brute-force attacks
- 🔄 **Easy Management** – Generate, regenerate, or remove URLs from the WordPress editor
- 📋 **Audit Logging** – Optional logging of preview access and suspicious activity
- 🎯 **Extensible** – Custom filters for access control and logging behavior
- ⚡ **Zero Configuration** – Works out of the box as an mu-plugin

---

## Installation

This plugin is already installed as a must-use plugin (mu-plugin) and is automatically loaded by WordPress. No additional setup required.

**Plugin Files:**
- Main Plugin: `/wp-content/mu-plugins/share-previews/share-previews.php`
- Documentation: `/wp-content/mu-plugins/share-previews/README.md`

Must-use plugins are automatically activated without needing to be enabled in the WordPress admin. WordPress loads all PHP files from the `/wp-content/mu-plugins/` directory (and subdirectories) on every page load.

---

## Usage

### For End Users (Content Editors)

1. Create a new draft post or page
2. In the WordPress editor sidebar, find the **Preview URL** meta box
3. Click **+ Generate Preview URL** to create a secure preview link
4. Click **Copy** to copy the URL to your clipboard
5. Share the URL with anyone who should review the draft
6. Use **🔄 Regenerate URL** to create a new URL (invalidates the old one)
7. Use **🗑️ Remove URL** to deactivate the preview link

### For Developers

#### Getting a Preview Link Programmatically

```php
<?php
$post_id = 123;
$preview_url = share_previews_get_draft_preview_link($post_id);

if ($preview_url) {
    echo "Share this link: " . $preview_url;
} else {
    echo "Post is not a draft or preview is not available.";
}
?>
```

#### Getting the Preview Key

```php
<?php
$post_id = 123;
$key = share_previews_get_preview_key($post_id);
echo "Preview Key: " . $key;
?>
```

#### Regenerating a Preview Key

```php
<?php
$post_id = 123;
$new_key = share_previews_regenerate_preview_key($post_id);
echo "New key: " . $new_key;
// The old key is now invalid
?>
```

---

## Filters & Hooks

### `share_previews_allow_preview`

Controls whether a specific draft post can be previewed. Use this filter to implement custom access control logic.

**Parameters:**
- `$allow` (bool) – Whether to allow the preview (default: true)
- `$post_id` (int) – The ID of the post being previewed
- `$post` (WP_Post) – The post object

**Returns:** bool – True to allow preview, false to deny

#### Example: Only Allow Previews for Specific Post Types

```php
<?php
add_filter('share_previews_allow_preview', function ($allow, $post_id, $post) {
    // Only allow previews for posts and pages, not custom post types
    if (!in_array($post->post_type, ['post', 'page'])) {
        return false;
    }
    return $allow;
}, 10, 3);
?>
```

#### Example: Restrict Previews to Specific User Roles

```php
<?php
add_filter('share_previews_allow_preview', function ($allow, $post_id, $post) {
    // Only allow previews if the post was created by an editor or admin
    $post_author = get_userdata($post->post_author);
    
    if ($post_author && !in_array('editor', (array) $post_author->roles) && 
        !in_array('administrator', (array) $post_author->roles)) {
        return false;
    }
    return $allow;
}, 10, 3);
?>
```

#### Example: Allow Previews Only for Specific Categories

```php
<?php
add_filter('share_previews_allow_preview', function ($allow, $post_id, $post) {
    // Only allow previews for posts in the "Public" category
    $categories = wp_get_post_categories($post_id);
    $public_category_id = get_cat_ID('Public');
    
    if ($post->post_type === 'post' && !in_array($public_category_id, $categories)) {
        return false;
    }
    return $allow;
}, 10, 3);
?>
```

#### Example: Limit Previews by Post Status Duration

```php
<?php
add_filter('share_previews_allow_preview', function ($allow, $post_id, $post) {
    // Only allow previews for posts that have been drafts for less than 7 days
    $post_date = strtotime($post->post_modified);
    $days_old = (time() - $post_date) / DAY_IN_SECONDS;
    
    if ($days_old > 7) {
        return false;
    }
    return $allow;
}, 10, 3);
?>
```

---

### `share_previews_enable_logging`

Controls whether preview access is logged. By default, logging is disabled. Enable it to track all preview accesses for security audits.

**Parameters:** None

**Returns:** bool – True to enable logging, false to disable

#### Example: Enable Access Logging

```php
<?php
add_filter('share_previews_enable_logging', '__return_true');
?>
```

Logs are written to `wp-content/debug.log` (if `WP_DEBUG_LOG` is enabled) with this format:

```
[Share Previews] Preview accessed: post_id=123, ip=192.168.1.100, time=2025-10-30 14:23:45
```

#### Example: Enable Logging Only for Admins

```php
<?php
add_filter('share_previews_enable_logging', function () {
    return current_user_can('manage_options');
});
?>
```

#### Example: Send Logs to External Service

```php
<?php
add_action('share_previews_log_preview_access', function ($post_id, $ip) {
    // Send to external logging service
    wp_remote_post('https://logs.example.com/api/preview', [
        'body' => json_encode([
            'post_id' => $post_id,
            'ip' => $ip,
            'site' => get_bloginfo('url'),
            'timestamp' => wp_date('c'),
        ]),
    ]);
}, 10, 2);
?>
```

---

## Suspicious Activity Logging

The plugin **always logs suspicious activity**, regardless of the `share_previews_enable_logging` filter. This includes:

- **invalid_key** – Someone tried to use an invalid or expired key
- **rate_limit_exceeded** – Too many attempts from the same IP (> 10 per minute)
- **key_regenerated** – A key was regenerated by an admin
- **generate_key** – A new key was generated

Logs are written to `wp-content/debug.log` with this format:

```
[Share Previews] SUSPICIOUS ACTIVITY: reason=invalid_key, post_id=123, ip=192.168.1.100, time=2025-10-30 14:23:45
```

---

## Database Schema

Preview keys are stored in the WordPress post meta table:

**Meta Key:** `_share_previews_key`  
**Meta Value:** 64-character hexadecimal string

Example query to find all posts with preview keys:

```sql
SELECT post_id, meta_value as preview_key
FROM wp_postmeta
WHERE meta_key = '_share_previews_key'
ORDER BY post_id DESC;
```

---

## Security Considerations

### Rate Limiting

The plugin enforces rate limiting to prevent brute-force attacks:

- **Limit:** 10 attempts per minute per IP address
- **Storage:** WordPress transients (cleared after 1 minute of inactivity)
- **Behavior:** Invalid attempts are logged and rejected

### Timing-Safe Comparison

Preview keys use `hash_equals()` for comparison, which prevents timing attacks where an attacker could guess the key character-by-character by measuring response times.

### Nonce Verification

All AJAX actions (generate, regenerate, remove) are protected with WordPress nonces to prevent CSRF attacks.

### Capability Checks

Only users with `edit_post` capability can manage preview URLs. The meta box displays a permissions notice if the user lacks access.

### IP Detection

The plugin safely detects client IP addresses and includes support for proxy headers:

- `REMOTE_ADDR` (primary, most reliable)
- `X-Forwarded-For` (if `SHARE_PREVIEWS_TRUST_PROXY_HEADERS` is defined)
- `CF-Connecting-IP` (Cloudflare)
- `X-Real-IP` (Nginx)

To enable proxy header support, add to `wp-config.php`:

```php
<?php
define('SHARE_PREVIEWS_TRUST_PROXY_HEADERS', true);
?>
```

---

## Function Reference

### `share_previews_get_draft_preview_link( $post_id )`

Generates a secure, shareable preview link for a draft post.

**Parameters:**
- `$post_id` (int) – The ID of the draft post

**Returns:** string|false – A fully qualified preview URL, or false if the post is not a draft or preview is not allowed

### `share_previews_get_preview_key( $post_id )`

Gets or generates a unique preview key for a post.

**Parameters:**
- `$post_id` (int) – The ID of the post

**Returns:** string – A unique 64-character preview key

### `share_previews_regenerate_preview_key( $post_id )`

Generates a new preview key for a post, invalidating the old one.

**Parameters:**
- `$post_id` (int) – The ID of the post

**Returns:** string – The newly generated preview key

### `share_previews_is_valid_draft_preview_key()`

Validates an incoming preview request. Checks the preview key, enforces rate limiting, and logs activity.

**Parameters:** None

**Returns:** bool – True if the preview key is valid, false otherwise

### `share_previews_get_client_ip()`

Safely detects the client IP address, handling proxy scenarios.

**Parameters:** None

**Returns:** string – The client IP address

### `share_previews_log_preview_access( $post_id, $ip )`

Logs successful preview access (only if `share_previews_enable_logging` returns true).

**Parameters:**
- `$post_id` (int) – The ID of the post being previewed
- `$ip` (string) – The IP address of the visitor

**Returns:** void

### `share_previews_log_suspicious_activity( $reason, $post_id, $ip )`

Always logs suspicious activity for security alerts.

**Parameters:**
- `$reason` (string) – The reason for logging (invalid_key, rate_limit_exceeded, etc.)
- `$post_id` (int) – The ID of the post being targeted
- `$ip` (string) – The IP address of the attacker

**Returns:** void

---

## Troubleshooting

### Preview URL Not Working

**Problem:** The preview URL returns a 404 or shows a blank page.

**Solution:** 
- Verify the post is still in draft status
- Check that the correct post ID is in the URL
- Ensure the preview key in the URL matches what's in the editor
- Check if a custom filter is blocking the preview with `share_previews_allow_preview`

### Rate Limit Exceeded

**Problem:** "Rate limit exceeded" error when accessing a preview URL.

**Solution:**
- Wait 1 minute before trying again
- Check `wp-content/debug.log` for suspicious activity
- If this happens frequently, the preview URL may have been shared publicly and attacked

### Preview Key Lost

**Problem:** I closed the browser without copying the preview URL and now I can't find it.

**Solution:**
- Go back to the post editor
- The preview URL is displayed in the meta box
- If the URL is lost but a key exists, click "Regenerate URL" to create a new one

### Logs Not Appearing

**Problem:** Preview access is not being logged even with `share_previews_enable_logging` enabled.

**Solution:**
- Enable WordPress debug logging by adding to `wp-config.php`:
  ```php
  define('WP_DEBUG', true);
  define('WP_DEBUG_LOG', true);
  define('WP_DEBUG_DISPLAY', false);
  ```
- Restart your browser after enabling the filter
- Check `wp-content/debug.log` for log entries

---

## Advanced Configuration

### Custom Logging Backend

```php
<?php
// Redirect all access logs to a custom logging system
add_action('share_previews_log_preview_access', function ($post_id, $ip) {
    // Example: Send to Slack
    wp_remote_post('https://hooks.slack.com/services/YOUR/WEBHOOK/URL', [
        'body' => json_encode([
            'text' => "Preview accessed: Post #$post_id from IP $ip",
            'icon_emoji' => ':eyes:',
        ]),
    ]);
}, 10, 2);
?>
```

### Dynamic Access Control

```php
<?php
add_filter('share_previews_allow_preview', function ($allow, $post_id, $post) {
    // Check custom metadata
    $allowed_roles = get_post_meta($post_id, '_preview_allowed_roles', true);
    
    if (!$allowed_roles) {
        return $allow; // No restrictions
    }
    
    $user = wp_get_current_user();
    $user_roles = (array) $user->roles;
    $has_access = array_intersect($user_roles, $allowed_roles);
    
    return !empty($has_access);
}, 10, 3);
?>
```

### Automatic Key Rotation

```php
<?php
// Regenerate all preview keys older than 30 days
add_action('wp_scheduled_event_share_previews_rotate_keys', function () {
    $args = [
        'post_type' => ['post', 'page'],
        'posts_per_page' => -1,
        'meta_key' => '_share_previews_key',
    ];
    
    $query = new WP_Query($args);
    
    foreach ($query->posts as $post) {
        $key_timestamp = get_post_meta($post->ID, '_share_previews_key_created', true);
        $age_days = (time() - $key_timestamp) / DAY_IN_SECONDS;
        
        if ($age_days > 30) {
            share_previews_regenerate_preview_key($post->ID);
            update_post_meta($post->ID, '_share_previews_key_created', time());
        }
    }
});

// Schedule the event (run once to set up)
if (!wp_next_scheduled('wp_scheduled_event_share_previews_rotate_keys')) {
    wp_schedule_event(time(), 'daily', 'wp_scheduled_event_share_previews_rotate_keys');
}
?>
```

---

## About ProVia

This plugin was developed by the **ProVia Marketing Team** to provide secure, flexible draft preview functionality for WordPress sites. For more information about ProVia, visit https://provia.com

## Support & Contributing

For issues, questions, or contributions, please contact the ProVia Marketing Team.

---

## Changelog

### Version 1.0.0 (October 30, 2025)

- Initial release
- Unique per-post preview keys
- Rate limiting (10 attempts per minute per IP)
- Audit logging with optional enable filter
- Meta box UI in post editor
- AJAX handlers for generate, regenerate, remove
- Security hardening: nonces, capability checks, timing-safe comparison
- Extensibility: `share_previews_allow_preview` and `share_previews_enable_logging` filters
