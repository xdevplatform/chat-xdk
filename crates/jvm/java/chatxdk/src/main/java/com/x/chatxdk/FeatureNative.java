package com.x.chatxdk;

import com.sun.jna.Library;
import com.sun.jna.Pointer;

/**
 * The cdylib's internal entry points for this package's feature switches. They are not part of
 * the C API, so they stay out of {@link ChatNative}.
 */
interface FeatureNative extends Library {

    FeatureNative INSTANCE = NativeLoader.load(FeatureNative.class);

    FfiResult.ByValue chat_xdk_internal_feature_start(Pointer handle);

    FfiResult.ByValue chat_xdk_internal_feature_complete(long id, int status, byte[] body, long bodyLen);

    FfiResult.ByValue chat_xdk_internal_feature_configure(
            Pointer handle, Pointer endpoint, long timeoutMs, long refreshMs);

    FfiResult.ByValue chat_xdk_internal_feature_set_default_endpoint(Pointer endpoint);
}
