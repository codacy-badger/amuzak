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

$web_path = AmpConfig::get('web_path');
?>

<ul id="sidebar-light">
    <li><a id="header-link" href="<?php echo $web_path ?>/jukebox.php?action=artist"><img src="<?php echo $web_path ?>/images/topmenu-artist.png" title="<?php echo T_('Artists') ?>" /><br /><?php echo T_('Artists') ?></a></li>
    <li><a id="header-link" href="<?php echo $web_path ?>/jukebox.php?action=album"><img src="<?php echo $web_path ?>/images/topmenu-album.png" title="<?php echo T_('Albums') ?>" /><br /><?php echo T_('Albums') ?></a></li>
    <li><a id="header-link" href="<?php echo $web_path ?>/jukebox.php?action=playlist"><img src="<?php echo $web_path ?>/images/topmenu-playlist.png" title="<?php echo T_('Playlists') ?>" /><br /><?php echo T_('Playlists') ?></a></li>
    <li><a id="header-link" href="<?php echo $web_path ?>/browse.php?action=smartplaylist"><img src="<?php echo $web_path ?>/images/topmenu-playlist.png" title="<?php echo T_('Smartlists') ?>" /><br /><?php echo T_('Smartlists') ?></a></li>
<?php if (AmpConfig::get('live_stream')) {
    ?>
    <li><a id="header-link" href="<?php echo $web_path ?>/browse.php?action=live_stream"><img src="<?php echo $web_path ?>/images/topmenu-radio.png" title="<?php echo T_('Radio Stations') ?>" /><br /><?php echo T_('Radio') ?></a></li>
<?php
} ?>
<?php if (AmpConfig::get('userflags') && Access::check('interface', 25)) {
        ?>
    <li><a id="header-link" href="<?php echo $web_path ?>/stats.php?action=userflag"><img src="<?php echo $web_path ?>/images/topmenu-favorite.png" title="<?php echo T_('Favorites') ?>" /><br /><?php echo T_('Favorites') ?></a></li>
<?php
    } ?>
</ul>
