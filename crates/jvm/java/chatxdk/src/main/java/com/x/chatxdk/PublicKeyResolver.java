package com.x.chatxdk;

import com.x.chatxdk.Types.PublicKeyRecord;

import java.util.List;
import java.util.Map;

/**
 * Fetches users' public keys for a {@link Chat}: set one with {@link Chat#setResolvePublicKeys},
 * and the chat calls it for the users whose keys a decrypt or a prepare call is missing.
 *
 * <p>An implementation makes one {@code GET /2/users/{id}/public_keys} request per user and
 * returns the records of each response's {@code data} array under that user's id.
 */
@FunctionalInterface
public interface PublicKeyResolver {

    /**
     * Fetch the public keys of {@code userIds}.
     *
     * @param userIds the users whose keys are missing, once each.
     * @return the records fetched, by user id. A user whose keys could not be fetched is left
     *     out or mapped to an empty list; the chat does not ask for the same key again for a
     *     minute. Null is read as no records.
     * @throws Exception to fail the call that ran the resolver: the chat rethrows it as is.
     */
    Map<String, List<PublicKeyRecord>> resolve(List<String> userIds) throws Exception;
}
