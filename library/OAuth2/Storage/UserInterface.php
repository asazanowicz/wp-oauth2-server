<?php

namespace OAuth2\Storage;

/**
 * Implement this interface to specify where the OAuth2 Server
 * should retrieve data involving the relevent scopes associated
 * with this implementation.
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
interface UserInterface 
{
    /**
     * Check if the provided scope exists.
     *
     * @param $user_id
     * WP user id.
     *
     * @return
     * User meta capabilities
     */
    public function getUserCapabilities($user_id);
}
