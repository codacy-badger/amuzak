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
<form style="display:inline;" name="f" method="get" action="<?php echo AmpConfig::get('web_path') . "/$action"; ?>" enctype="multipart/form-data">
    <label for="match" accesskey="S"><?php echo $text; ?></label>
    <input type="text" id="match" name="match" value="<?php echo $match; ?>" />
    <input type="hidden" name="action" value="<?php echo scrub_out($_REQUEST['action']); ?>">
</form>
