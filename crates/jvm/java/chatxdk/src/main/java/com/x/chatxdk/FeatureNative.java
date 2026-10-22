package com.x.chatxdk;

import com.sun.jna.Library;
import com.sun.jna.Pointer;

/**
 * The cdylib's internal entry points for this package's feature switches. They are not part of
 * the C API, so they stay out of {@link ChatNative}.
 */
interface FeatureNative extends Library {

    FeatureNative INSTANCE = NativeLoader.load(FeatureNative.class);

    int chat_xdk_internal_feature_bucket(Pointer handle);

    FfiResult.ByValue chat_xdk_internal_apply_feature_config(
            Pointer handle, Pointer json, int bucket, int downgradeOnly);

    int chat_xdk_internal_is_enabled(Pointer handle, Pointer name);

    int chat_xdk_internal_feature_refetch_due(Pointer handle);
}
