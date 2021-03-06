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
?>
<?php UI::show_box_top(T_('Create a new playlist')); ?>
<form name="songs" method="post" action="<?php echo AmpConfig::get('web_path'); ?>/playlist.php">
    <table class="tabledata" cellspacing="0" cellpadding="0">
        <tr>
            <td><?php echo T_('Name'); ?>:</td>
            <td><input type="text" name="playlist_name" /></td>
        </tr>
        <tr>
            <td><?php echo T_('Type'); ?>:</td>
            <td>
                <select name="type">
                    <option value="private"> Private </option>
                    <option value="public"> Public </option>
                </select>
            </td>
        </tr>
    </table>
    <div class="formValidation">
        <input class="button" type="submit" value="<?php echo T_('Create'); ?>" />
        <input type="hidden" name="action" value="Create" />
    </div>
</form>
<?php UI::show_box_bottom(); ?>
