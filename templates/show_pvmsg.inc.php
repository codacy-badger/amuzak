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

UI::show_box_top($pvmsg->f_subject, 'info-box');
?>
<div>
    <?php echo T_('Sent by') . ' ' . $pvmsg->f_from_user_link . ' at ' . $pvmsg->f_creation_date; ?>
</div>
<div id="information_actions">
    <h3><?php echo T_('Actions'); ?>:</h3>

    <ul>
        <li>
            <a id="<?php echo 'reply_pvmsg_' . $label->id ?>" href="<?php echo AmpConfig::get('web_path'); ?>/pvmsg.php?action=show_add_message&reply_to=<?php echo $pvmsg->id; ?>">
                <?php echo UI::get_icon('mail', T_('Reply')); ?> <?php echo T_('Reply'); ?>
            </a>
        </li>
    </ul>
</div>

<hr />
<div>
    <?php echo nl2br($pvmsg->f_message); ?>
</div>

<?php UI::show_box_bottom(); ?>
