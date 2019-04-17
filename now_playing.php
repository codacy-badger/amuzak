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

/* Check Perms */
if (!AmpConfig::get('use_now_playing_embedded') || AmpConfig::get('demo_mode')) {
    UI::access_denied();

    return false;
}

?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="<?php echo $htmllang; ?>" lang="<?php echo $htmllang; ?>" dir="<?php echo is_rtl(AmpConfig::get('lang')) ? 'rtl' : 'ltr';?>">
<head>
    <!-- Propulsed by Ampache | ampache.org -->
    <meta http-equiv="Content-Type" content="application/xhtml+xml; charset=<?php echo AmpConfig::get('site_charset'); ?>" />
    <meta name="viewport" content="width=1024, initial-scale=1.0">
    <title><?php echo AmpConfig::get('site_title'); ?> - Now Playing</title>
<?php
if (AmpConfig::get('now_playing_css_file')) {
    ?>
    <link rel="stylesheet" href="<?php echo $web_path;
    echo AmpConfig::get('now_playing_css_file'); ?>" type="text/css" media="screen" />
<?php
}
if (AmpConfig::get('now_playing_refresh_limit') > 1) {
    $refresh_limit = AmpConfig::get('now_playing_refresh_limit'); ?>
    <script type="text/javascript" language="javascript">
        reload = window.setInterval(function(){ window.location.reload(); }, <?php echo $refresh_limit ?> * 1000);
    </script>
<?php
} ?>
</head>
<body>
<?php

Stream::gc_now_playing();
$results = Stream::get_now_playing();

if ($_REQUEST['user_id']) {
    // If the URL specifies a specific user, filter the results on that user
    $results = array_filter($results, function ($item) {
        return ($item['client']->id == $_REQUEST['user_id']);
    });
}

require AmpConfig::get('prefix') . UI::find_template('show_now_playing.inc.php');
?>
</body>
</html>
