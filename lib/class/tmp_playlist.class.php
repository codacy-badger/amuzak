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
 * TempPlaylist Class
 *
 * This class handles the temporary playlists in Ampache. It handles the
 * tmp_playlist and tmp_playlist_data tables, and sneaks out at night to
 * visit user_vote from time to time.
 *
 */
class Tmp_Playlist extends database_object
{
    /* Variables from the Datbase */
    public $id;
    public $session;
    public $type;
    public $object_type;
    public $base_playlist;

    /* Generated Elements */
    public $items = array();

    /**
     * Constructor
     * This takes a playlist_id as an optional argument and gathers the
     * information.  If no playlist_id is passed or the requested one isn't
     * found, return false.
     */
    public function __construct($playlist_id='')
    {
        if (!$playlist_id) {
            return false;
        }

        $this->id     = (int) ($playlist_id);
        $info         = $this->_get_info();

        foreach ($info as $key => $value) {
            $this->$key = $value;
        }

        return true;
    } // __construct

    /**
     * _get_info
     * This is an internal (private) function that gathers the information
     * for this object from the playlist_id that was passed in.
     */
    private function _get_info()
    {
        $sql        = "SELECT * FROM `tmp_playlist` WHERE `id`='" . Dba::escape($this->id) . "'";
        $db_results = Dba::read($sql);

        $results = Dba::fetch_assoc($db_results);

        return $results;
    } // _get_info

    /**
     * get_from_session
     * This returns a playlist object based on the session that is passed to
     * us.  This is used by the load_playlist on user for the most part.
     * @param string $session_id
     */
    public static function get_from_session($session_id)
    {
        $session_id = Dba::escape($session_id);

        $sql        = "SELECT `id` FROM `tmp_playlist` WHERE `session`='$session_id'";
        $db_results = Dba::read($sql);

        $results = Dba::fetch_row($db_results);

        if (!$results['0']) {
            $results['0'] = self::create(array(
                'session_id' => $session_id,
                'type' => 'user',
                'object_type' => 'song'
            ));
        }

        $playlist = new Tmp_Playlist($results['0']);

        return $playlist;
    } // get_from_session

    /**
     * get_from_userid
     * This returns a tmp playlist object based on a userid passed
     * this is used for the user profiles page
     */
    public static function get_from_userid($user_id)
    {
        // This is a little stupid, but because we don't have the
        // user_id in the session or in the tmp_playlist table we have
        // to do it this way.
        $client   = new User($user_id);
        $username = Dba::escape($client->username);

        $sql = "SELECT `tmp_playlist`.`id` FROM `tmp_playlist` " .
            "LEFT JOIN `session` ON " .
            "`session`.`id`=`tmp_playlist`.`session` " .
            "WHERE `session`.`username`='$username' " .
            "ORDER BY `session`.`expire` DESC";
        $db_results = Dba::read($sql);

        $data = Dba::fetch_assoc($db_results);

        return $data['id'];
    } // get_from_userid

    /**
     * get_items
     * Returns an array of all object_ids currently in this Tmp_Playlist.
     */
    public function get_items()
    {
        /* Select all objects from this playlist */
        $sql = "SELECT `object_type`, `id`, `object_id` " .
            "FROM `tmp_playlist_data` " .
            "WHERE `tmp_playlist` = ? ORDER BY `id` ASC";
        $db_results = Dba::read($sql, array($this->id));

        /* Define the array */
        $items = array();

        $i = 1;
        while ($results = Dba::fetch_assoc($db_results)) {
            $items[]     = array(
                'object_type' => $results['object_type'],
                'object_id' => $results['object_id'],
                'track_id' => $results['id'],
                'track' => $i++,
            );
        }

        return $items;
    } // get_items

    /**
     * get_next_object
     * This returns the next object in the tmp_playlist.
     */
    public function get_next_object()
    {
        $list_id = Dba::escape($this->id);

        $sql = "SELECT `object_id` FROM `tmp_playlist_data` " .
            "WHERE `tmp_playlist`='$list_id' ORDER BY `id` LIMIT 1";
        $db_results = Dba::read($sql);

        $results = Dba::fetch_assoc($db_results);

        return $results['object_id'];
    } // get_next_object

    /**
     * count_items
     * This returns a count of the total number of tracks that are in this
     * tmp playlist
     */
    public function count_items()
    {
        $list_id = Dba::escape($this->id);

        $sql = "SELECT COUNT(`id`) FROM `tmp_playlist_data` WHERE " .
            "`tmp_playlist`='$list_id'";
        $db_results = Dba::read($sql);

        $results = Dba::fetch_row($db_results);

        return $results['0'];
    } // count_items

    /**
      * clear
     * This clears all the objects out of a single playlist
     */
    public function clear()
    {
        $sql = "DELETE FROM `tmp_playlist_data` WHERE `tmp_playlist` = ?";
        Dba::write($sql, array($this->id));

        return true;
    } // clear

    /**
     * create
     * This function initializes a new Tmp_Playlist. It is associated with
     * the current session rather than a user, as you could have the same
     * user logged in from multiple locations.
     */
    public static function create($data)
    {
        $sql = "INSERT INTO `tmp_playlist` " .
            "(`session`,`type`,`object_type`) " .
            " VALUES (?, ?, ?)";
        Dba::write($sql, array($data['session_id'], $data['type'], $data['object_type']));

        $list_id = Dba::insert_id();

        /* Clean any other playlists associated with this session */
        self::session_clean($data['session_id'], $list_id);

        return $list_id;
    } // create

    /**
     * update_playlist
     * This updates the base_playlist on this tmp_playlist
     */
    public function update_playlist($playlist_id)
    {
        $sql = "UPDATE `tmp_playlist` SET " .
            "`base_playlist`= ? WHERE `id`= ?";
        Dba::write($sql, array($playlist_id, $this->id));

        return true;
    } // update_playlist

    /**
     * session_clean
     * This deletes any other tmp_playlists associated with this
     * session
     */
    public static function session_clean($sessid, $list_id)
    {
        $sql = "DELETE FROM `tmp_playlist` WHERE `session`= ? AND `id` != ?";
        Dba::write($sql, array($sessid, $list_id));

        /* Remove associated tracks */
        self::prune_tracks();

        return true;
    } // session_clean

    /**
     * gc
     * This cleans up old data
     */
    public static function gc()
    {
        self::prune_playlists();
        self::prune_tracks();
        //Dba::write("DELETE FROM `tmp_playlist_data` USING `tmp_playlist_data` LEFT JOIN `song` ON `tmp_playlist_data`.`object_id` = `song`.`id` WHERE `song`.`id` IS NULL");
    }

    /**
     * prune_playlists
     * This deletes any playlists that don't have an associated session
     */
    public static function prune_playlists()
    {
        /* Just delete if no matching session row */
        $sql = "DELETE FROM `tmp_playlist` USING `tmp_playlist` " .
            "LEFT JOIN `session` " .
            "ON `session`.`id`=`tmp_playlist`.`session` " .
            "WHERE `session`.`id` IS NULL " .
            "AND `tmp_playlist`.`type` != 'vote'";
        Dba::write($sql);

        return true;
    } // prune_playlists

    /**
     * prune_tracks
     * This prunes tracks that don't have playlists or don't have votes
     */
    public static function prune_tracks()
    {
        // This prune is always run and clears data for playlists that
        // don't exist anymore
        $sql = "DELETE FROM `tmp_playlist_data` USING " .
            "`tmp_playlist_data` LEFT JOIN `tmp_playlist` ON " .
            "`tmp_playlist_data`.`tmp_playlist`=`tmp_playlist`.`id` " .
            "WHERE `tmp_playlist`.`id` IS NULL";
        Dba::write($sql);
    } // prune_tracks

    /**
     * add_object
     * This adds the object of $this->object_type to this tmp playlist
     * it takes an optional type, default is song
     */
    public function add_object($object_id, $object_type)
    {
        $sql = "INSERT INTO `tmp_playlist_data` " .
            "(`object_id`,`tmp_playlist`,`object_type`) " .
            " VALUES (?, ?, ?)";
        Dba::write($sql, array($object_id, $this->id, $object_type));

        return true;
    } // add_object

    public function add_medias($medias)
    {
        foreach ($medias as $media) {
            $this->add_object($media['object_id'], $media['object_type']);
        }
    }

    /**
     * vote_active
     * This checks to see if this playlist is a voting playlist
     * and if it is active
     */
    public function vote_active()
    {
        /* Going to do a little more here later */
        if ($this->type == 'vote') {
            return true;
        }

        return false;
    } // vote_active

    /**
     * delete_track
     * This deletes a track from the tmpplaylist
     */
    public function delete_track($song_id)
    {
        /* delete the track its self */
        $sql = "DELETE FROM `tmp_playlist_data` WHERE `id` = ?";
        Dba::write($sql, array($song_id));

        return true;
    } // delete_track
} // class Tmp_Playlist
