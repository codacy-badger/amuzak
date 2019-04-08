<?php
/* vim:set softtabstop=4 shiftwidth=4 expandtab: */
/**
 *
 * LICENSE: GNU Affero General Public License, version 3 (AGPLv3)
 * Copyright 2019 ampcore
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

require_once 'lib/init.php';

UI::show_header_tiny();

//$action = isset($_REQUEST['action']) ? scrub_in($_REQUEST['action']) : null;

if (!Core::is_session_started()) {
    session_start();
}
$_SESSION['catalog'] = 0;

$object_type = $_REQUEST['action'];

/**
 * Check for the refresh mojo, if it's there then require the
 * refresh_javascript include. Must be greater then 5, I'm not
 * going to let them break their servers
 */
if (AmpConfig::get('refresh_limit') > 5 && AmpConfig::get('home_now_playing')) {
    $refresh_limit = AmpConfig::get('refresh_limit');
    $ajax_url      = '?page=index&action=reloadnp';
    require_once AmpConfig::get('prefix') . UI::find_template('javascript_refresh.inc.php');
}

if (Art::is_enabled()) {
    if (AmpConfig::get('home_moment_albums')) {
        echo Ajax::observe('window', 'load', Ajax::action('?page=index&action=random_albums', 'random_albums')); ?>
<div id="random_selection" class="random_selection">
    <?php UI::show_box_top(T_('Albums of the Moment'));
        echo T_('Loading...');
        UI::show_box_bottom(); ?>
</div>
<?php
    }
}
if (Core::is_library_item($object_type)) {
    require_once AmpConfig::get('prefix') . UI::find_template('show_mashup.inc.php');
}
UI::show_footer();
