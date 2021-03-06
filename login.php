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

define('NO_SESSION', '1');
require_once 'lib/init.php';
// Avoid form login if still connected
if (AmpConfig::get('use_auth') && !isset($_GET['force_display'])) {
    $auth = false;
    if (Session::exists('interface', $_COOKIE[AmpConfig::get('session_name')])) {
        $auth = true;
    } else {
        if (Session::auth_remember()) {
            $auth = true;
        }
    }
    if ($auth) {
        header("Location: " . AmpConfig::get('web_path'));
        exit;
    }
}
require_once 'lib/login.php';

require AmpConfig::get('prefix') . UI::find_template('show_login_form.inc.php');
