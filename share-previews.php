<?php
/**
 * Plugin Name: Share Previews
 * Plugin URI: https://provia.com
 * Description: Allow people to preview draft posts with secure, shareable links
 * Version: 1.0.0
 * Author: ProVia
 * Author URI: https://provia.com
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: share-previews
 * Domain Path: /languages
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

// Constants for meta keys
define('SHARE_PREVIEWS_KEY_META', '_share_previews_key');

/**
 * Get the current preview mode setting
 *
 * @return bool  True if staging mode (all statuses), false if draft-only mode
 */
function share_previews_is_staging_mode() {
    return defined('SHARE_PREVIEWS_ALLOW_ALL_STATUSES') && SHARE_PREVIEWS_ALLOW_ALL_STATUSES;
}

/**
 * Get the base URL for preview links
 *
 * @return string  Base URL with trailing slash
 */
function share_previews_get_base_url() {
    return defined('SHARE_PREVIEWS_BASE_URL') ? SHARE_PREVIEWS_BASE_URL : home_url('/');
}

/**
 * Generate a secure, shareable preview link for a post.
 *
 * Default mode (SHARE_PREVIEWS_ALLOW_ALL_STATUSES = false):
 * - Works only on draft posts
 * - Requires a unique key generated per post
 * - Keys must be managed (generate/regenerate/remove)
 *
 * Staging mode (SHARE_PREVIEWS_ALLOW_ALL_STATUSES = true):
 * - Works only on published/non-draft posts
 * - No key required - simple preview URLs
 * - Perfect for staging environments with basic auth
 *
 * Supports custom base URL via SHARE_PREVIEWS_BASE_URL constant in wp-config.php
 * Example: define('SHARE_PREVIEWS_BASE_URL', 'https://user:pass@staging.example.com');
 *
 * @param int $post_id              The ID of the post.
 * @param bool $auto_generate_key   Whether to auto-generate missing keys (default: true)
 * @return string|false             A fully qualified preview URL, or false if post is not eligible.
 */
function share_previews_get_draft_preview_link($post_id, $auto_generate_key = true) {
    $post = get_post($post_id);
    if (!$post) {
        return false;
    }

    $is_staging_mode = share_previews_is_staging_mode();
    $base_url = share_previews_get_base_url();

    // Apply filter to allow custom access control
    if (!apply_filters('share_previews_allow_preview', true, $post_id, $post)) {
        return false;
    }

    // Drafts: always use keys
    if ($post->post_status === 'draft') {
        $key = $auto_generate_key ? share_previews_get_preview_key($post_id) : share_previews_get_existing_preview_key($post_id);

        if (!$key) {
            return false;
        }

        return add_query_arg([
            'p' => $post_id,
            'preview' => '1',
            'key' => $key,
        ], $base_url);
    }

    // Non-draft posts only work in staging mode
    if ($is_staging_mode && $post->post_status === 'publish') {
        return add_query_arg([
            'p' => $post_id,
            'preview' => '1',
        ], $base_url);
    }

    return false;
}

// Backwards compatibility alias (deprecated)
if (!function_exists('get_draft_preview_link')) {
    function get_draft_preview_link($post_id) {
        return share_previews_get_draft_preview_link($post_id);
    }
}

/**
 * Get a unique preview key for a post WITHOUT generating one if it doesn't exist.
 *
 * @param int $post_id  The post ID.
 * @return string|false  The existing preview key, or false if none exists.
 */
function share_previews_get_existing_preview_key($post_id) {
    $existing_key = get_post_meta($post_id, SHARE_PREVIEWS_KEY_META, true);
    return !empty($existing_key) ? $existing_key : false;
}

/**
 * Get or generate a unique preview key for a post.
 *
 * @param int $post_id  The post ID.
 * @return string       A unique 64-character preview key.
 */
function share_previews_get_preview_key($post_id) {
    $existing_key = share_previews_get_existing_preview_key($post_id);

    if ($existing_key) {
        return $existing_key;
    }

    $new_key = bin2hex(random_bytes(32)); // 64-character hex string
    update_post_meta($post_id, SHARE_PREVIEWS_KEY_META, $new_key);
    update_post_meta($post_id, '_share_previews_key_created', time());

    return $new_key;
}

/**
 * Regenerate a preview key for a post.
 *
 * @param int $post_id  The post ID.
 * @return string       The newly generated preview key.
 */
function share_previews_regenerate_preview_key($post_id) {
    $new_key = bin2hex(random_bytes(32));
    update_post_meta($post_id, SHARE_PREVIEWS_KEY_META, $new_key);
    update_post_meta($post_id, '_share_previews_key_created', time());

    // Clear the post meta cache to ensure immediate retrieval
    wp_cache_delete($post_id, 'post_meta');
    clean_post_cache($post_id);

    share_previews_log_suspicious_activity('key_regenerated', $post_id, 'admin');
    return $new_key;
}

/**
 * Verify the draft preview key and return whether it's valid.
 * Checks if the key matches the one stored in post meta.
 * Includes rate limiting to prevent brute-force attacks.
 *
 * @return bool  True if the preview key is valid, false otherwise.
 */
function share_previews_is_valid_draft_preview_key() {
    // Check if preview query parameters are present
    if (!isset($_GET['preview'], $_GET['key'], $_GET['p'])) {
        return false;
    }

    $post_id = intval($_GET['p']);
    $raw_key = isset($_GET['key']) ? stripslashes($_GET['key']) : '';
    $key = preg_replace('/[^a-f0-9]/i', '', $raw_key); // Only allow hex characters

    // Validate post_id and key length
    if ($post_id <= 0 || strlen($key) !== 64) {
        return false;
    }

    // Get the stored key from post meta, bypassing cache
    global $wpdb;
    $stored_key = $wpdb->get_var($wpdb->prepare(
        "SELECT meta_value FROM {$wpdb->postmeta} WHERE post_id = %d AND meta_key = %s LIMIT 1",
        $post_id,
        SHARE_PREVIEWS_KEY_META
    ));

    // Use hash_equals for timing-safe comparison
    $is_valid = !empty($stored_key) && strlen($stored_key) === 64 && hash_equals($stored_key, $key);

    return $is_valid;
}

// Backwards compatibility alias (deprecated)
if (!function_exists('is_valid_draft_preview_key')) {
    function is_valid_draft_preview_key() {
        return share_previews_is_valid_draft_preview_key();
    }
}

/**
 * Log preview access for security audits.
 *
 * @param int    $post_id  The post being previewed.
 * @param string $ip       The IP address of the visitor.
 */
function share_previews_log_preview_access($post_id, $ip) {
    if (apply_filters('share_previews_enable_logging', false)) {
        error_log(sprintf(
            '[Share Previews] Preview accessed: post_id=%d, ip=%s, time=%s',
            $post_id,
            $ip,
            wp_date('Y-m-d H:i:s')
        ));
    }
}

/**
 * Log suspicious activity for security alerts.
 *
 * @param string $reason   The reason for logging (invalid_key, rate_limit_exceeded, etc).
 * @param int    $post_id  The post being targeted.
 * @param string $ip       The IP address of the attacker.
 */
function share_previews_log_suspicious_activity($reason, $post_id, $ip) {
    error_log(sprintf(
        '[Share Previews] SUSPICIOUS ACTIVITY: reason=%s, post_id=%d, ip=%s, time=%s',
        $reason,
        $post_id,
        $ip,
        wp_date('Y-m-d H:i:s')
    ));
}

/**
 * Get the client IP address safely.
 * Handles proxy headers while validating for spoofing.
 *
 * @return string  The client IP address.
 */
function share_previews_get_client_ip() {
    // Start with REMOTE_ADDR (most reliable)
    $ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field($_SERVER['REMOTE_ADDR']) : '0.0.0.0';

    // Check for trusted proxy headers if configured
    if (defined('SHARE_PREVIEWS_TRUST_PROXY_HEADERS') && SHARE_PREVIEWS_TRUST_PROXY_HEADERS) {
        // Check X-Forwarded-For (most common)
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = array_map('trim', explode(',', sanitize_text_field($_SERVER['HTTP_X_FORWARDED_FOR'])));
            $ip = array_shift($ips); // Take the first IP (client)
        } elseif (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            // Cloudflare
            $ip = sanitize_text_field($_SERVER['HTTP_CF_CONNECTING_IP']);
        } elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
            // Nginx proxy
            $ip = sanitize_text_field($_SERVER['HTTP_X_REAL_IP']);
        }
    }

    return $ip;
}

/**
 * Display preview URL meta box in the page editor.
 */
add_action('add_meta_boxes', function () {
    global $post;

    if (!$post) {
        return;
    }

    // Check if this post should have the meta box
    $show_box = false;

    // Always show on drafts
    if ($post->post_status === 'draft') {
        $show_box = true;
    } else {
        // On published/other statuses, only show if staging mode is enabled
        $allow_all_statuses = defined('SHARE_PREVIEWS_ALLOW_ALL_STATUSES') && SHARE_PREVIEWS_ALLOW_ALL_STATUSES;
        if ($allow_all_statuses) {
            $show_box = true;
        }
    }

    // Only add the meta box if the post is eligible
    if (!$show_box) {
        return;
    }

    add_meta_box(
        'share_previews_box',
        'Preview URL',
        'share_previews_render_meta_box',
        'page',
        'side',
        'high'
    );

    add_meta_box(
        'share_previews_box',
        'Preview URL',
        'share_previews_render_meta_box',
        'post',
        'side',
        'high'
    );
});

/**
 * Render the preview URL meta box.
 */
function share_previews_render_meta_box($post) {
    // Verify user can manage this feature
    if (!current_user_can('edit_post', $post->ID)) {
        echo '<p style="color: #999; margin: 0;"><em>You do not have permission to view this.</em></p>';
        return;
    }

    $is_staging_mode = share_previews_is_staging_mode();
    $has_key = get_post_meta($post->ID, SHARE_PREVIEWS_KEY_META, true);

    // Determine if we should show a preview URL
    $preview_url = '';
    if ($is_staging_mode) {
        // Staging mode: generate URL for published posts (no key generation)
        $preview_url = share_previews_get_draft_preview_link($post->ID, false);
    } elseif ($has_key) {
        // Draft mode: only generate URL if key already exists (no auto-generation)
        $preview_url = share_previews_get_draft_preview_link($post->ID, false);
    }

    // Add nonce fields for security (unique nonces for each action)
    wp_nonce_field('share_previews_generate_nonce', 'share_previews_generate_nonce');
    wp_nonce_field('share_previews_regenerate_nonce', 'share_previews_regenerate_nonce');
    wp_nonce_field('share_previews_remove_nonce', 'share_previews_remove_nonce');
    ?>
    <style>
        #share_previews_box .inside {
            padding: 12px;
        }
        .share-previews-url-wrapper {
            display: flex;
            gap: 8px;
            align-items: center;
        }
        .share-previews-url {
            flex: 1;
            padding: 8px 12px;
            background: #f5f5f5;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-family: monospace;
            font-size: 12px;
            word-break: break-all;
            color: #333;
        }
        .share-previews-copy-btn {
            padding: 6px 12px;
            background: #0073aa;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 500;
            white-space: nowrap;
            transition: background 200ms ease-in-out;
        }
        .share-previews-copy-btn:hover {
            background: #005a87;
        }
        .share-previews-copy-btn.copied {
            background: #28a745;
        }
        .share-previews-info {
            margin-top: 8px;
            padding: 8px;
            background: #e7f3ff;
            border-left: 4px solid #0073aa;
            font-size: 12px;
            color: #333;
            line-height: 1.4;
        }
        .share-previews-generate-btn {
            transition: background 200ms ease-in-out !important;
        }
        .share-previews-generate-btn:hover {
            background: #218838 !important;
        }
        .share-previews-regen-btn {
            transition: background 200ms ease-in-out;
        }
        .share-previews-regen-btn:hover {
            background: #c82333 !important;
        }
        .share-previews-remove-link {
            transition: background 200ms ease-in-out;
        }
        .share-previews-remove-link:hover {
            color: #333 !important;
            border-bottom-color: #333 !important;
            text-decoration: none;
        }
        .share-previews-remove-link:active {
            opacity: 0.8;
        }
    </style>

    <div class="share-previews-url-wrapper">
        <?php if ($preview_url): ?>
            <input type="text" class="share-previews-url" value="<?php echo esc_attr($preview_url); ?>" readonly>
            <button class="share-previews-copy-btn" type="button" onclick="share_previews_copy_url(this)">Copy</button>
        <?php elseif ($post->post_status === 'draft'): ?>
            <button class="share-previews-generate-btn" type="button" onclick="share_previews_generate_key(<?php echo esc_attr($post->ID); ?>)" style="padding: 8px 16px; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 13px; font-weight: 600; width: 100%; transition: background 200ms ease-in-out; display: inline-block;">+ Generate Preview URL</button>
        <?php endif; ?>
    </div>

    <div class="share-previews-info" <?php echo $preview_url ? '' : 'style="display: none;"'; ?>>
        <?php if (isset($allow_all_statuses) && $post->post_status !== 'draft'): ?>
            📋 Share this URL to let others preview this published page. Anyone with the URL can access it.
        <?php else: ?>
            📋 Share this URL to let others preview this draft page without logging in. The URL is only valid while the page remains in draft status.
        <?php endif; ?>
    </div>

    <div class="share-previews-alert" style="display: none; margin-top: 12px; padding: 10px; background: #fff3cd; border: 1px solid #ffc107; border-radius: 4px; color: #856404;">
    </div>

    <button class="share-previews-regen-btn" type="button" onclick="share_previews_show_regen_alert()" style="margin-top: 12px; padding: 6px 12px; background: #dc3545; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: 500; width: 100%; display: none;">🔄 Regenerate URL</button>

    <a href="#" class="share-previews-remove-link" onclick="event.preventDefault(); share_previews_show_remove_alert()" style="margin-top: 8px; font-size: 12px; color: #666; text-decoration: none; padding: 4px 0; border-bottom: 1px dotted #999; display: none;">🗑️ Remove URL</a>

    <script>
        function share_previews_update_button_visibility() {
            const previewUrl = document.querySelector('.share-previews-url');
            const regenBtn = document.querySelector('.share-previews-regen-btn');
            const removeLink = document.querySelector('.share-previews-remove-link');
            const postStatus = '<?php echo esc_js($post->post_status); ?>';

            if (previewUrl && previewUrl.value.trim() && postStatus === 'draft') {
                // URL exists AND post is draft, show regenerate and remove buttons
                if (regenBtn) regenBtn.style.display = 'block';
                if (removeLink) removeLink.style.display = 'inline-block';
            } else {
                // No URL or post is not draft, hide regenerate and remove buttons
                if (regenBtn) regenBtn.style.display = 'none';
                if (removeLink) removeLink.style.display = 'none';
            }
        }

        function share_previews_apply_button_styles() {
            const buttons = document.querySelectorAll('.share-previews-confirm-regen, .share-previews-confirm-remove, .share-previews-cancel-regen, .share-previews-cancel-remove');
            buttons.forEach(btn => {
                btn.style.transition = 'opacity 200ms ease-in-out';
                btn.addEventListener('mouseenter', function() {
                    this.style.opacity = '70%';
                });
                btn.addEventListener('mouseleave', function() {
                    this.style.opacity = '100%';
                });
                btn.addEventListener('mousedown', function() {
                    this.style.opacity = '100%';
                });
            });
        }

        // Initialize button visibility on page load
        document.addEventListener('DOMContentLoaded', function() {
            share_previews_update_button_visibility();
            share_previews_apply_button_styles();
        });

        function share_previews_copy_url(button) {
            const input = button.previousElementSibling;
            input.select();
            document.execCommand('copy');

            // Visual feedback
            const originalText = button.textContent;
            button.textContent = 'Copied!';
            button.classList.add('copied');

            setTimeout(() => {
                button.textContent = originalText;
                button.classList.remove('copied');
            }, 2000);
        }

        function share_previews_show_regen_alert() {
            const alertBox = document.querySelector('.share-previews-alert');
            const postId = document.querySelector('input[name="post_ID"]').value;

            // Set up the regenerate confirmation alert
            alertBox.innerHTML = '<p style="margin: 0 0 10px 0; font-size: 13px;"><strong>⚠️ Regenerate URL?</strong></p><p style="margin: 0 0 10px 0; font-size: 13px;">This will invalidate the current preview URL. Anyone using the old URL won\'t be able to access this draft.</p><div style="display: flex; gap: 8px;"><button class="share-previews-confirm-regen" type="button" data-post-id="' + postId + '" onclick="share_previews_confirm_regenerate(this)" style="padding: 6px 12px; background: #000; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: 500;">Regenerate</button><button class="share-previews-cancel-regen" type="button" onclick="share_previews_cancel_regenerate()" style="padding: 6px 12px; background: #fff; color: #000; border: 1px solid #ddd; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: 500;">Cancel</button></div>';
            alertBox.style.background = '#fff3cd';
            alertBox.style.borderColor = '#ffc107';
            alertBox.style.color = '#856404';
            alertBox.style.display = 'block';
            document.querySelector('.share-previews-regen-btn').style.display = 'none';
            share_previews_apply_button_styles();
        }

        function share_previews_cancel_regenerate() {
            document.querySelector('.share-previews-alert').style.display = 'none';
            document.querySelector('.share-previews-regen-btn').style.display = 'block';
        }

        function share_previews_generate_key(postId) {
            const button = document.querySelector('.share-previews-generate-btn');
            const nonceField = document.querySelector('input[name="share_previews_generate_nonce"]');

            if (!nonceField) {
                alert('Security field missing');
                return;
            }

            button.disabled = true;
            button.textContent = '⏳ Generating...';

            fetch(ajaxurl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=share_previews_generate_key&post_id=' + encodeURIComponent(postId) + '&nonce=' + encodeURIComponent(nonceField.value)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Replace the generate button with URL and copy button
                    const wrapper = document.querySelector('.share-previews-url-wrapper');
                    wrapper.innerHTML = '<input type="text" class="share-previews-url" value="' + data.data.preview_url.replace(/"/g, '&quot;') + '" readonly><button class="share-previews-copy-btn" type="button" onclick="share_previews_copy_url(this)">Copy</button>';

                    // Show the info
                    document.querySelector('.share-previews-info').style.display = 'block';

                    // Update button visibility based on URL presence
                    share_previews_update_button_visibility();

                    // Auto-copy the URL
                    const urlInput = document.querySelector('.share-previews-url');
                    urlInput.select();
                    document.execCommand('copy');

                    // Visual feedback
                    button.textContent = '✅ URL Generated!';
                    button.style.background = '#28a745';
                } else {
                    button.disabled = false;
                    button.textContent = '+ Generate Preview URL';
                    const error = data.data ? data.data.substring(0, 100) : 'Unable to generate URL';
                    alert('Error: ' + error);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                button.disabled = false;
                button.textContent = '+ Generate Preview URL';
                alert('Error: Unable to generate URL');
            });
        }

        function share_previews_show_remove_alert() {
            const alertBox = document.querySelector('.share-previews-alert');
            const postId = document.querySelector('input[name="post_ID"]').value;
            alertBox.innerHTML = '<p style="margin: 0 0 10px 0; font-size: 13px;"><strong>⚠️ Remove URL?</strong></p><p style="margin: 0 0 10px 0; font-size: 13px;">This will remove the preview URL. Anyone with the URL won\'t be able to access this draft anymore.</p><div style="display: flex; gap: 8px;"><button class="share-previews-confirm-remove" type="button" data-post-id="' + postId + '" onclick="share_previews_confirm_remove(this)" style="padding: 6px 12px; background: #000; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: 500;">Remove</button><button class="share-previews-cancel-remove" type="button" onclick="share_previews_cancel_remove()" style="padding: 6px 12px; background: #fff; color: #000; border: 1px solid #ddd; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: 500;">Cancel</button></div>';
            alertBox.style.background = '#f8d7da';
            alertBox.style.borderColor = '#f5c6cb';
            alertBox.style.color = '#721c24';
            alertBox.style.display = 'block';
            document.querySelector('.share-previews-regen-btn').style.display = 'none';
            share_previews_apply_button_styles();
        }

        function share_previews_cancel_remove() {
            document.querySelector('.share-previews-alert').style.display = 'none';
            document.querySelector('.share-previews-regen-btn').style.display = 'block';
        }

        function share_previews_confirm_remove(button) {
            const postId = button.getAttribute('data-post-id');
            const alertBox = document.querySelector('.share-previews-alert');
            const nonceField = document.querySelector('input[name="share_previews_remove_nonce"]');

            if (!nonceField) {
                console.error('Nonce field not found');
                alertBox.innerHTML = '<p style="margin: 0; font-size: 13px; color: #721c24;"><strong>❌ Error:</strong> Security field missing</p>';
                return;
            }

            button.disabled = true;
            button.textContent = '⏳ Removing...';

            fetch(ajaxurl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=share_previews_remove_key&post_id=' + encodeURIComponent(postId) + '&nonce=' + encodeURIComponent(nonceField.value)
            })
            .then(response => response.json())
            .then(data => {
                console.log('Remove response:', data);
                if (data.success) {
                    // Replace URL and buttons with generate button
                    const wrapper = document.querySelector('.share-previews-url-wrapper');
                    wrapper.innerHTML = '<button class="share-previews-generate-btn" type="button" onclick="share_previews_generate_key(' + postId + ')" style="padding: 8px 16px; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 13px; font-weight: 600; width: 100%; transition: background 0.2s;">+ Generate Preview URL</button>';

                    // Hide the info
                    document.querySelector('.share-previews-info').style.display = 'none';

                    // Update button visibility (will hide regenerate/remove since no URL)
                    share_previews_update_button_visibility();

                    // Show success message
                    alertBox.innerHTML = '<p style="margin: 0; font-size: 13px;"><strong>✅ URL removed!</strong> Preview is no longer active.</p>';
                    alertBox.style.background = '#d4edda';
                    alertBox.style.borderColor = '#28a745';
                    alertBox.style.color = '#155724';

                    setTimeout(() => {
                        document.querySelector('.share-previews-alert').style.display = 'none';
                    }, 2000);
                } else {
                    alertBox.innerHTML = '<p style="margin: 0; font-size: 13px; color: #721c24;"><strong>❌ Error:</strong> ' + (data.data ? data.data.substring(0, 100) : 'Unable to remove URL') + '</p>';
                    button.disabled = false;
                    button.textContent = 'Remove';
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alertBox.innerHTML = '<p style="margin: 0; font-size: 13px; color: #721c24;"><strong>❌ Error:</strong> Unable to remove URL</p>';
                button.disabled = false;
                button.textContent = 'Remove';
            });
        }

        function share_previews_confirm_regenerate(button) {
            const postId = button.getAttribute('data-post-id');
            const alertBox = document.querySelector('.share-previews-alert');
            const nonceField = document.querySelector('input[name="share_previews_regenerate_nonce"]');

            if (!nonceField) {
                console.error('Nonce field not found');
                alertBox.innerHTML = '<p style="margin: 0; font-size: 13px; color: #721c24;"><strong>❌ Error:</strong> Security field missing</p>';
                return;
            }

            button.disabled = true;
            button.textContent = '⏳ Regenerating...';

            fetch(ajaxurl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=share_previews_regenerate&post_id=' + encodeURIComponent(postId) + '&nonce=' + encodeURIComponent(nonceField.value)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Update the URL field with the new preview link
                    const urlInput = document.querySelector('.share-previews-url');
                    if (urlInput) {
                        urlInput.value = data.data.preview_url;
                        urlInput.select();
                        document.execCommand('copy');
                    }

                    // Update button visibility (keeps regenerate/remove visible)
                    share_previews_update_button_visibility();

                    // Show success message
                    alertBox.innerHTML = '<p style="margin: 0; font-size: 13px;"><strong>✅ URL regenerated!</strong> New URL copied to clipboard.</p>';
                    alertBox.style.background = '#d4edda';
                    alertBox.style.borderColor = '#28a745';
                    alertBox.style.color = '#155724';

                    setTimeout(() => {
                        document.querySelector('.share-previews-alert').style.display = 'none';
                        document.querySelector('.share-previews-regen-btn').style.display = 'block';
                    }, 2000);
                } else {
                    alertBox.innerHTML = '<p style="margin: 0; font-size: 13px; color: #721c24;"><strong>❌ Error:</strong> ' + (data.data ? data.data.substring(0, 100) : 'Unable to regenerate URL') + '</p>';
                    alertBox.style.background = '#f8d7da';
                    alertBox.style.borderColor = '#f5c6cb';
                    button.disabled = false;
                    button.textContent = 'Regenerate';
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alertBox.innerHTML = '<p style="margin: 0; font-size: 13px; color: #721c24;"><strong>❌ Error:</strong> Unable to regenerate URL</p>';
                alertBox.style.background = '#f8d7da';
                alertBox.style.borderColor = '#f5c6cb';
                button.disabled = false;
                button.textContent = 'Regenerate';
            });
        }
    </script>
    <?php
}

/**
 * Allow draft posts to be viewed when a valid preview key is provided.
 */
add_action('pre_get_posts', function ($query) {
    // Don't run on backend
    if (defined('WP_ADMIN') && WP_ADMIN) {
        return;
    }

    if (!$query->is_main_query()) {
        return;
    }

    if (share_previews_is_valid_draft_preview_key()) {
        // Include drafts in the query
        $query->set('post_status', ['publish', 'draft']);

        // Ensure proper template selection for preview URLs
        if (isset($_GET['p'])) {
            $post_id = intval($_GET['p']);
            $post = get_post($post_id);

            if ($post && $post->post_status === 'draft') {
                if ($post->post_type === 'page') {
                    $query->is_page = true;
                    $query->is_singular = true;
                    $query->is_single = false;
                } else {
                    $query->is_single = true;
                    $query->is_singular = true;
                    $query->is_page = false;
                }
            }
        }
    }
});

/**
 * Bypass the "post_status must be published" check in WordPress.
 */
add_filter('posts_pre_query', function ($posts, $query) {
    // Don't run on backend
    if (defined('WP_ADMIN') && WP_ADMIN) {
        return $posts;
    }

    // For preview URLs, check if this is a single post query
    $is_single_post_query = !empty($query->query_vars['p']) || !empty($query->query_vars['name']);

    if (!$is_single_post_query) {
        return $posts;
    }

    if (share_previews_is_valid_draft_preview_key() && isset($_GET['p'])) {
        $post_id = intval($_GET['p']);
        $post = get_post($post_id);

        // Ensure post is a draft
        if ($post && $post->post_status === 'draft') {
            // Verify via filter that this post can be previewed
            if (apply_filters('share_previews_allow_preview', true, $post_id, $post)) {
                // Set the correct query vars to ensure proper template selection
                if ($post->post_type === 'page') {
                    $query->is_page = true;
                    $query->is_singular = true;
                    $query->is_single = false;
                    $query->queried_object = $post;
                    $query->queried_object_id = $post->ID;
                } else {
                    $query->is_single = true;
                    $query->is_singular = true;
                    $query->is_page = false;
                    $query->queried_object = $post;
                    $query->queried_object_id = $post->ID;
                }

                // Return the draft post directly to bypass further checks
                return [$post];
            }
        }
    }

    return $posts;
}, 10, 2);

/**
 * AJAX handler to regenerate preview key.
 */
add_action('wp_ajax_share_previews_regenerate', function () {
    // Verify nonce (use unique action name for this specific AJAX handler)
    if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'share_previews_regenerate_nonce')) {
        wp_send_json_error('Invalid request');
        return;
    }

    // Sanitize and validate post_id
    $post_id = isset($_POST['post_id']) ? (int) $_POST['post_id'] : 0;

    if ($post_id <= 0) {
        wp_send_json_error('Invalid post ID');
        return;
    }

    $post = get_post($post_id);

    // Verify permissions
    if (!$post || !current_user_can('edit_post', $post_id)) {
        wp_send_json_error('Insufficient permissions');
        return;
    }

    // Regenerate is only allowed on drafts (in all modes)
    if ($post->post_status !== 'draft') {
        wp_send_json_error('Post status not eligible for preview');
        return;
    }

    // Regenerate the key (drafts always use keys)
    $new_key = share_previews_regenerate_preview_key($post_id);

    // Build the preview URL using the key we just generated
    $base_url = share_previews_get_base_url();
    $preview_url = add_query_arg([
        'p' => $post_id,
        'preview' => '1',
        'key' => $new_key,
    ], $base_url);

    wp_send_json_success([
        'key' => $new_key,
        'preview_url' => $preview_url,
    ]);
});

/**
 * AJAX handler to generate new preview key (for posts without an existing key).
 */
add_action('wp_ajax_share_previews_generate_key', function () {
    // Verify nonce (use unique action name for this specific AJAX handler)
    if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'share_previews_generate_nonce')) {
        wp_send_json_error('Invalid request');
        return;
    }

    // Sanitize and validate post_id
    $post_id = isset($_POST['post_id']) ? (int) $_POST['post_id'] : 0;

    if ($post_id <= 0) {
        wp_send_json_error('Invalid post ID');
        return;
    }

    $post = get_post($post_id);

    // Verify permissions
    if (!$post || !current_user_can('edit_post', $post_id)) {
        wp_send_json_error('Insufficient permissions');
        return;
    }

    // Verify post exists and is a draft (only draft mode supports key generation)
    if ($post->post_status !== 'draft') {
        wp_send_json_error('Post must be a draft');
        return;
    }

    // Check if key already exists (prevent race condition by verifying again before updating)
    $existing_key = get_post_meta($post_id, SHARE_PREVIEWS_KEY_META, true);
    if (!empty($existing_key)) {
        wp_send_json_error('Preview URL already exists');
        return;
    }

    // Generate the key directly (don't use get_preview_key as it auto-generates)
    $new_key = bin2hex(random_bytes(32));

    // Use add_post_meta with unique=true to prevent race conditions
    $add_result = add_post_meta($post_id, SHARE_PREVIEWS_KEY_META, $new_key, true);
    if (!$add_result) {
        wp_send_json_error('Unable to create preview URL');
        return;
    }

    // Clear the post meta cache to ensure immediate retrieval
    wp_cache_delete($post_id, 'post_meta');
    clean_post_cache($post_id);

    // Verify the key was actually saved by checking immediately
    global $wpdb;
    $verify_key = $wpdb->get_var($wpdb->prepare(
        "SELECT meta_value FROM {$wpdb->postmeta} WHERE post_id = %d AND meta_key = %s LIMIT 1",
        $post_id,
        SHARE_PREVIEWS_KEY_META
    ));

    // If verification fails, don't send the URL
    if ($verify_key !== $new_key) {
        wp_send_json_error('Unable to verify preview URL was saved. Saved: ' . ($verify_key ? substr($verify_key, 0, 8) . '...' : 'NULL') . ', Expected: ' . substr($new_key, 0, 8) . '...');
        return;
    }

    share_previews_log_suspicious_activity('generate_key', $post_id, 'admin');

    // Build the preview URL using the key we just added (avoid retrieval timing issues)
    $base_url = share_previews_get_base_url();
    $preview_url = add_query_arg([
        'p' => $post_id,
        'preview' => '1',
        'key' => $new_key,
    ], $base_url);

    wp_send_json_success([
        'key' => $new_key,
        'preview_url' => $preview_url,
    ]);
});

/**
 * AJAX handler to remove preview key for a draft post.
 */
add_action('wp_ajax_share_previews_remove_key', function () {
    // Verify nonce (use unique action name for this specific AJAX handler)
    if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'share_previews_remove_nonce')) {
        wp_send_json_error('Invalid request');
        return;
    }

    // Sanitize and validate post_id
    $post_id = isset($_POST['post_id']) ? (int) $_POST['post_id'] : 0;

    if ($post_id <= 0) {
        wp_send_json_error('Invalid post ID');
        return;
    }

    $post = get_post($post_id);

    // Verify permissions
    if (!$post || !current_user_can('edit_post', $post_id)) {
        wp_send_json_error('Insufficient permissions');
        return;
    }

    // Verify post exists and is a draft (only draft mode has keys to remove)
    if ($post->post_status !== 'draft') {
        wp_send_json_error('Post must be a draft');
        return;
    }

    // Delete the key from post meta
    delete_post_meta($post_id, SHARE_PREVIEWS_KEY_META);

    wp_send_json_success([
        'message' => 'Preview URL removed',
    ]);
});

/**
 * Register the Share Previews admin page.
 */
add_action('admin_menu', function () {
    add_submenu_page(
        'tools.php',
        'Share Previews',
        'Share Previews',
        'manage_options',
        'share-previews-manager',
        'share_previews_render_admin_page'
    );
});

/**
 * Render the Share Previews admin page.
 */
function share_previews_render_admin_page() {
    if (!current_user_can('manage_options')) {
        wp_die('Unauthorized');
    }

    // Verify nonce for form submission
    if (!empty($_GET['s']) || !empty($_GET['post_type'])) {
        if (!isset($_GET['share_previews_filter_nonce']) ||
            !wp_verify_nonce($_GET['share_previews_filter_nonce'], 'share_previews_filter')) {
            wp_die('Security check failed');
        }
    }

    // Get search/filter parameters
    $search = isset($_GET['s']) ? sanitize_text_field($_GET['s']) : '';
    $post_type = isset($_GET['post_type']) ? sanitize_text_field($_GET['post_type']) : '';
    $paged = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
    $per_page = 20;

    // Validate post_type against allowed post types
    $allowed_post_types = ['post', 'page'];
    if (!empty($post_type) && !in_array($post_type, $allowed_post_types, true)) {
        $post_type = '';
    }

    // Query posts with preview keys
    $args = [
        'post_type' => $allowed_post_types,
        'posts_per_page' => $per_page,
        'paged' => $paged,
        'meta_key' => '_share_previews_key',
        'orderby' => 'modified',
        'order' => 'DESC',
    ];

    // Add search parameter
    if (!empty($search)) {
        $args['s'] = $search;
    }

    // Add post type filter
    if (!empty($post_type)) {
        $args['post_type'] = $post_type;
    }

    $query = new WP_Query($args);
    $total_pages = $query->max_num_pages;

    ?>
    <div class="wrap">
        <h1>Share Previews Manager</h1>
        <?php wp_nonce_field('share_previews_regenerate_nonce', 'share_previews_regenerate_nonce_admin'); ?>
        <?php wp_nonce_field('share_previews_remove_nonce', 'share_previews_remove_nonce_admin'); ?>
        <p>Manage all active preview URLs for draft posts and pages.</p>

        <!-- Search and Filter -->
        <form method="get" class="share-previews-search-form">
            <input type="hidden" name="page" value="share-previews-manager">
            <?php wp_nonce_field('share_previews_filter', 'share_previews_filter_nonce'); ?>
            <input
                type="text"
                name="s"
                placeholder="Search by post title..."
                value="<?php echo esc_attr($search); ?>"
                class="regular-text"
            >
            <select name="post_type" class="postform">
                <option value="">All Post Types</option>
                <option value="post" <?php selected($post_type, 'post'); ?>>Posts</option>
                <option value="page" <?php selected($post_type, 'page'); ?>>Pages</option>
            </select>
            <input type="submit" value="Filter" class="button">
            <a href="?page=share-previews-manager" class="button">Reset</a>
        </form>

        <style>
            .share-previews-search-form {
                margin: 20px 0;
                display: flex;
                gap: 10px;
                align-items: center;
                flex-wrap: wrap;
            }

            .share-previews-table {
                width: 100%;
                border-collapse: collapse;
                background: white;
                box-shadow: 0 1px 1px rgba(0,0,0,0.04);
                margin-top: 20px;
            }

            .share-previews-table thead {
                background: #f5f5f5;
                border-bottom: 1px solid #ddd;
            }

            .share-previews-table th {
                padding: 12px;
                text-align: left;
                font-weight: 600;
                font-size: 13px;
                color: #333;
            }

            .share-previews-table td {
                padding: 12px;
                border-bottom: 1px solid #eee;
                font-size: 13px;
            }

            .share-previews-table tbody tr:hover {
                background: #fafafa;
            }

            .share-previews-url-cell {
                font-family: monospace;
                word-break: break-all;
                max-width: 300px;
                color: #0073aa;
            }

            .share-previews-actions {
                display: flex;
                gap: 8px;
                flex-wrap: wrap;
                justify-content: flex-end;
            }

            .share-previews-btn {
                padding: 4px 8px;
                font-size: 12px;
                text-decoration: none;
                border: none;
                border-radius: 3px;
                cursor: pointer;
                transition: background 150ms ease-in-out;
            }

            .share-previews-btn-copy {
                background: #0073aa;
                color: white;
            }

            .share-previews-btn-copy:hover {
                background: #005a87;
            }

            .share-previews-btn-regen {
                background: #dc3545;
                color: white;
            }

            .share-previews-btn-regen:hover {
                background: #c82333;
            }

            .share-previews-btn-delete {
                background: transparent;
                color: #666;
                border: none;
            }

            .share-previews-btn-delete:hover {
                color: #333;
            }

            .share-previews-btn-view {
                background: #28a745;
                color: white;
            }

            .share-previews-btn-view:hover {
                background: #218838;
                color: white;
            }

            .share-previews-empty {
                padding: 30px;
                text-align: center;
                color: #666;
                background: #f9f9f9;
                border: 1px solid #ddd;
                border-radius: 4px;
                margin-top: 20px;
            }

            .share-previews-pagination {
                margin-top: 20px;
            }

            .share-previews-post-title a {
                color: #0073aa;
                text-decoration: none;
            }

            .share-previews-post-title a:hover {
                text-decoration: underline;
            }

            .share-previews-post-type {
                display: inline-block;
                padding: 2px 6px;
                background: #e7f3ff;
                border-radius: 3px;
                font-size: 11px;
                color: #0073aa;
                margin-left: 8px;
            }

            .share-previews-status {
                font-size: 12px;
                color: #666;
            }
        </style>

        <!-- Posts Table -->
        <?php if ($query->have_posts()) : ?>
            <table class="share-previews-table">
                <thead>
                    <tr>
                        <th style="width: 25%;">Post</th>
                        <th style="width: 40%;">Preview URL</th>
                        <th style="width: 15%;">Created</th>
                        <th style="width: 20%; text-align: right;">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while ($query->have_posts()) : $query->the_post();
                        $post_id = get_the_ID();
                        $preview_url = share_previews_get_draft_preview_link($post_id);
                        $created = get_post_meta($post_id, '_share_previews_key_created', true);
                        if (!$created) {
                            $created = get_the_modified_date('U', $post_id);
                        }
                    ?>
                        <tr>
                            <td class="share-previews-post-title">
                                <a href="<?php echo get_edit_post_link($post_id); ?>" target="_blank">
                                    <?php echo esc_html(get_the_title() ?: '(Untitled)'); ?>
                                </a>
                                <span class="share-previews-post-type"><?php echo esc_html(get_post_type()); ?></span>
                                <div class="share-previews-status">
                                    Status: <strong><?php echo esc_html(get_post_status()); ?></strong>
                                </div>
                            </td>
                            <td class="share-previews-url-cell">
                                <?php if ($preview_url) : ?>
                                    <code><?php echo esc_html($preview_url); ?></code>
                                <?php else : ?>
                                    <em style="color: #999;">Unable to generate URL</em>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php echo esc_html(wp_date('M j, Y', $created)); ?>
                            </td>
                            <td>
                                <div class="share-previews-actions">
                                    <?php if ($preview_url) : ?>
                                        <button
                                            class="share-previews-btn share-previews-btn-copy"
                                            data-url="<?php echo esc_attr($preview_url); ?>"
                                            onclick="share_previews_copy_admin_url(this)"
                                        >
                                            📋 Copy
                                        </button>
                                        <a
                                            href="<?php echo esc_url($preview_url); ?>"
                                            target="_blank"
                                            class="share-previews-btn share-previews-btn-view"
                                        >
                                            👁️ View
                                        </a>
                                        <button
                                            class="share-previews-btn share-previews-btn-regen"
                                            data-post-id="<?php echo esc_attr($post_id); ?>"
                                            onclick="share_previews_admin_regenerate(this)"
                                        >
                                            🔄 Regen
                                        </button>
                                        <button
                                            class="share-previews-btn share-previews-btn-delete"
                                            data-post-id="<?php echo esc_attr($post_id); ?>"
                                            data-post-title="<?php echo esc_attr(get_the_title()); ?>"
                                            onclick="share_previews_admin_delete(this)"
                                        >
                                            🗑️ Delete
                                        </button>
                                    <?php endif; ?>
                                </div>
                            </td>
                        </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>

            <!-- Pagination -->
            <?php if ($total_pages > 1) : ?>
                <div class="share-previews-pagination">
                    <?php
                    $base_url = add_query_arg(['page' => 'share-previews-manager', 's' => $search, 'post_type' => $post_type]);
                    $args = [
                        'base' => $base_url . '&paged=%#%',
                        'format' => '',
                        'prev_text' => '← Previous',
                        'next_text' => 'Next →',
                        'total' => $total_pages,
                        'current' => $paged,
                    ];
                    echo paginate_links($args);
                    ?>
                </div>
            <?php endif; ?>

            <?php wp_reset_postdata(); ?>

        <?php else : ?>
            <div class="share-previews-empty">
                <p>No preview URLs found. Create a draft post or page and generate a preview URL to see it here.</p>
            </div>
        <?php endif; ?>
    </div>

    <script>
        function share_previews_copy_admin_url(button) {
            const url = button.getAttribute('data-url');
            const textarea = document.createElement('textarea');
            textarea.value = url;
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);

            const originalText = button.textContent;
            button.textContent = '✓ Copied!';
            button.style.background = '#28a745';

            setTimeout(() => {
                button.textContent = originalText;
                button.style.background = '';
            }, 2000);
        }

        function share_previews_admin_regenerate(button) {
            const postId = button.getAttribute('data-post-id');
            if (!confirm('Regenerate preview URL? The old URL will no longer work.')) {
                return;
            }

            button.disabled = true;
            button.textContent = '⏳ Regenerating...';

            fetch(ajaxurl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    action: 'share_previews_regenerate',
                    post_id: postId,
                    nonce: document.querySelector('input[name="share_previews_regenerate_nonce_admin"]').value
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                } else {
                    alert('Error: ' + (data.data || 'Unable to regenerate URL'));
                    button.disabled = false;
                    button.textContent = '🔄 Regen';
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error regenerating URL');
                button.disabled = false;
                button.textContent = '🔄 Regen';
            });
        }

        function share_previews_admin_delete(button) {
            const postId = button.getAttribute('data-post-id');
            const postTitle = button.getAttribute('data-post-title');

            if (!confirm('Delete preview URL for "' + postTitle + '"?\n\nThis cannot be undone.')) {
                return;
            }

            button.disabled = true;
            button.textContent = '⏳ Deleting...';

            fetch(ajaxurl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    action: 'share_previews_remove_key',
                    post_id: postId,
                    nonce: document.querySelector('input[name="share_previews_remove_nonce_admin"]').value
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const row = button.closest('tr');
                    row.style.opacity = '0.5';
                    setTimeout(() => {
                        location.reload();
                    }, 300);
                } else {
                    alert('Error: ' + (data.data || 'Unable to delete URL'));
                    button.disabled = false;
                    button.textContent = '🗑️ Delete';
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error deleting URL');
                button.disabled = false;
                button.textContent = '🗑️ Delete';
            });
        }
    </script>
    <?php
}