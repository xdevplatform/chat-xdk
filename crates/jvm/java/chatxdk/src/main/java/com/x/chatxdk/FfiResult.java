package com.x.chatxdk;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

/** Native {@code FfiResult} from the Rust FFI (two nullable UTF-8 string pointers). */
@Structure.FieldOrder({"data", "error"})
public class FfiResult extends Structure {

    /** Pointer to the UTF-8 success payload, or {@code null} on error. */
    public Pointer data;
    /** Pointer to the UTF-8 error message, or {@code null} on success. */
    public Pointer error;

    public static class ByValue extends FfiResult implements Structure.ByValue {}
}
