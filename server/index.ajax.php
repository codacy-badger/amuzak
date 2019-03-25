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

/**
 * Sub-Ajax page, requires AJAX_INCLUDE
 */
if (!defined('AJAX_INCLUDE')) {
    exit;
}

$results = array();
switch ($_REQUEST['action']) {
    case 'random_albums':
        $albums = Album::get_random(6);
        if (count($albums) and is_array($albums)) {
            ob_start();
            require_once AmpConfig::get('prefix') . UI::find_template('show_random_albums.inc.php');
            $results['random_selection'] = ob_get_clean();
        } else {
            $results['random_selection'] = '<!-- None found -->';

            if (Access::check('interface', '100')) {
                $catalogs = Catalog::get_catalogs();
                if (count($catalogs) == 0) {
                    $results['random_selection'] = sprintf(T_('No catalog configured yet. To start streaming your media, you now need to %s add a catalog %s'), '<a href="' . AmpConfig::get('web_path') . '/admin/catalog.php?action=show_add_catalog">', '</a>.<br /><br />');
                }
            }
        }
    break;
    case 'artist_info':
        if (AmpConfig::get('lastfm_api_key') && (isset($_REQUEST['artist']) || isset($_REQUEST['fullname']))) {
            if ($_REQUEST['artist']) {
                $artist = new Artist($_REQUEST['artist']);
                $artist->format();
                $biography = Recommendation::get_artist_info($artist->id);
            } else {
                $biography = Recommendation::get_artist_info(null, rawurldecode($_REQUEST['fullname']));
            }
            ob_start();
            require_once AmpConfig::get('prefix') . UI::find_template('show_artist_info.inc.php');
            $results['artist_biography'] = ob_get_clean();
        }
    break;
    case 'similar_artist':
        if (AmpConfig::get('show_similar') && isset($_REQUEST['artist'])) {
            $artist = new Artist($_REQUEST['artist']);
            $artist->format();
            $object_ids      = array();
            $missing_objects = array();
            if ($similars = Recommendation::get_artists_like($artist->id, 10, true)) {
                foreach ($similars as $similar) {
                    if ($similar['id']) {
                        $object_ids[] = $similar['id'];
                    } else {
                        $missing_objects[] = $similar;
                    }
                }
            }
            ob_start();
            require_once AmpConfig::get('prefix') . UI::find_template('show_recommended_artists.inc.php');
            $results['similar_artist'] = ob_get_clean();
        }
    break;
    case 'similar_now_playing':
        $media_id = $_REQUEST['media_id'];
        if (AmpConfig::get('show_similar') && isset($media_id) && isset($_REQUEST['media_artist'])) {
            $artists = Recommendation::get_artists_like($_REQUEST['media_artist'], 3, false);
            $songs   = Recommendation::get_songs_like($media_id, 3);
            ob_start();
            require_once AmpConfig::get('prefix') . UI::find_template('show_now_playing_similar.inc.php');
            $results['similar_items_' . $media_id] = ob_get_clean();
        }
    break;
    case 'concerts':
        if (AmpConfig::get('show_concerts') && isset($_REQUEST['artist'])) {
            $artist = new Artist($_REQUEST['artist']);
            $artist->format();
            if ($artist->id) {
                $up_concerts     = Artist_Event::get_upcoming_events($artist);
                $past_concerts   = Artist_Event::get_past_events($artist);
                $coming_concerts = array();
                $concerts        = array();
                if ($up_concerts) {
                    foreach ($up_concerts->children() as $item) {
                        if ($item->getName() == 'event') {
                            $coming_concerts[] = $item;
                        }
                    }
                }
                if ($past_concerts) {
                    foreach ($past_concerts->children() as $item) {
                        if ($item->getName() == 'event') {
                            $concerts[] = $item;
                        }
                    }
                }
            }
            ob_start();
            require_once AmpConfig::get('prefix') . UI::find_template('show_concerts.inc.php');
            $results['concerts'] = ob_get_clean();
        }
    break;
    case 'labels':
        if (AmpConfig::get('label') && isset($_REQUEST['artist'])) {
            $labels     = Label::get_labels($_REQUEST['artist']);
            $object_ids = array();
            if (count($labels) > 0) {
                foreach ($labels as $id => $label) {
                    $object_ids[] = $id;
                }
            }
            $browse = new Browse();
            $browse->set_type('label');
            $browse->set_simple_browse(false);
            $browse->save_objects($object_ids);
            $browse->store();
            ob_start();
            require_once AmpConfig::get('prefix') . UI::find_template('show_labels.inc.php');
            $results['labels'] = ob_get_clean();
        }
    break;
    case 'reloadnp':
        ob_start();
        show_now_playing();
        $results['now_playing'] = ob_get_clean();
        ob_start();
        $data = Song::get_recently_played();
        Song::build_cache(array_keys($data));
        require_once AmpConfig::get('prefix') . UI::find_template('show_recently_played.inc.php');
        $results['recently_played'] = ob_get_clean();
    break;
    case 'sidebar':
        switch ($_REQUEST['button']) {
            case 'home':
            case 'modules':
            case 'player':
            case 'preferences':
                $button = $_REQUEST['button'];
            break;
            case 'admin':
                if (Access::check('interface', '100')) {
                    $button = $_REQUEST['button'];
                } else {
                    exit;
                }
            break;
            default:
                exit;
        } // end switch on button

        Ajax::set_include_override(true);
        ob_start();
        $_SESSION['state']['sidebar_tab'] = $button;
        require_once AmpConfig::get('prefix') . UI::find_template('sidebar.inc.php');
        $results['sidebar-content'] = ob_get_contents();
        ob_end_clean();
    break;
    case 'slideshow':
        ob_start();
        $images = Slideshow::get_current_slideshow();
        if (count($images) > 0) {
            $fsname = 'fslider_' . time();
            echo "<div id='" . $fsname . "'>";
            foreach ($images as $image) {
                echo "<img src='" . $image['url'] . "' alt='' onclick='update_action();' />";
            }
            echo "</div>";
            $results['fslider'] = ob_get_clean();
            ob_start();
            echo "<script language='javascript' type='text/javascript'>";
            echo "$('#" . $fsname . "').rhinoslider({
                    showTime: 15000,
                    effectTime: 2000,
                    randomOrder: true,
                    controlsPlayPause: false,
                    autoPlay: true,
                    showBullets: 'never',
                    showControls: 'always',
                    controlsMousewheel: false,
            });";
            echo "</script>";
        }
        $results['fslider_script'] = ob_get_clean();
    break;
    case 'songs':
        $label_id = intval($_REQUEST['label']);

        ob_start();
        if ($label_id > 0) {
            $label      = new Label($label_id);
            $object_ids = $label->get_songs();

            $browse = new Browse();
            $browse->set_type('song');
            $browse->set_simple_browse(false);
            $browse->save_objects($object_ids);
            $browse->store();

            UI::show_box_top(T_('Songs'), 'info-box');
            require_once AmpConfig::get('prefix') . UI::find_template('show_songs.inc.php');
            UI::show_box_bottom();
        }

        $results['songs'] = ob_get_contents();
        ob_end_clean();
    break;
    default:
        $results['rfc3514'] = '0x1';
    break;
} // switch on action;

// We always do this
echo xoutput_from_array($results);
