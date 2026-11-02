# Load the build under test instead of an installed package with a different ABI.
set build_dir [lindex $argv 0]
source [file join $build_dir pkgIndex.tcl]
set version [package require tink]
if {[file normalize [lindex [lindex [info loaded] end] 0]] ne
    [file normalize [file join $build_dir libtink-tcl[info sharedlibextension]]]} {
    error "The test loaded a different tink library"
}

set plaintext [binary format H* 00017f80feff]
set keyset [::tink::register_keyset [::tink::aead::create_keyset AES256_GCM]]
try {
    set encrypted [::tink::aead::encrypt $keyset $plaintext context]
    if {[::tink::aead::decrypt $keyset $encrypted context] ne $plaintext} {
        error "AEAD round trip failed"
    }
    if {![catch {::tink::aead::decrypt $keyset $encrypted wrong-context}]} {
        error "AEAD accepted incorrect associated data"
    }
} finally {
    ::tink::unregister_keyset $keyset
}

set keyset [::tink::register_keyset [::tink::mac::create_keyset HMAC_SHA256]]
try {
    set tag [::tink::mac::compute $keyset $plaintext]
    if {![::tink::mac::verify $keyset $tag $plaintext]} {error "MAC verification failed"}
    if {[::tink::mac::verify $keyset $tag changed]} {error "MAC accepted changed data"}
} finally {
    ::tink::unregister_keyset $keyset
}

puts "tink $version loaded on Tcl [info patchlevel]; AEAD and MAC checks passed"
