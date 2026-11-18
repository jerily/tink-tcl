set build_dir [lindex $argv 0]
set argv {}
source [file join $build_dir pkgIndex.tcl]
package require tink 20240704.0.3
package require tjson 1.0.28
package require tcltest
namespace import ::tcltest::test
set claims {M {iss {S issuer} sub {S user} aud {L {{S client} {S api}}} exp {N 1300} iat {N 1000} verified {BOOL 1} number {N 42} null {N null} profile {M {name {S test}}} array {L {{N 1} {S two}}}}}
foreach algorithm {RS256_2048_F4 ES256 HS256} {
    test jwt-$algorithm {typed claims roundtrip with asymmetric or MAC primitives} -body {
        set key [::tink::register_keyset [::tink::jwt::create_private_keyset $algorithm]]
        set mac [expr {$algorithm eq "HS256"}]
        set sign [expr {$mac ? "::tink::jwt::mac_sign" : "::tink::jwt::sign"}]
        set verify [expr {$mac ? "::tink::jwt::mac_verify" : "::tink::jwt::verify"}]
        set public [expr {$mac ? $key : [::tink::jwt::import_jwks [::tink::jwt::export_jwks $key]]}]
        set token [$sign $key $claims JWT]
        set policy {issuer issuer audience client now 1100 type JWT}
        set payload [lindex [::tjson::json_to_typed_strict [$verify $public $token $policy]] 1]
        set result [list [dict get $payload verified] [dict get $payload null] [dict get $payload profile] \
            [catch {$verify $public $token [dict replace $policy type wrong]}] \
            [catch {$verify $public $token [dict replace $policy audience wrong]}] \
            [catch {$verify $public $token [dict replace $policy now 1400]}] \
            [catch {$verify $public [string replace $token end end !] $policy}]]
        if {!$mac} {::tink::unregister_keyset $public}
        ::tink::unregister_keyset $key
        set result
    } -result {{BOOL 1} {N null} {M {name {S test}}} 1 1 1 1}
}
test jwt-invalid {malformed keys and claims raise Tcl errors, without crashes} -body {
    set key [::tink::register_keyset [::tink::jwt::create_private_keyset RS256_2048_F4]]
    set result [list [catch {::tink::jwt::import_jwks broken}] [catch {::tink::jwt::jwk_set_to_public_keyset broken}] \
        [catch {::tink::jwt::sign $key {M {exp {S tomorrow}}}}] [catch {::tink::jwt::sign $key {M {foo {N NaN}}}}]]
    ::tink::unregister_keyset $key
    lappend result [catch {::tink::jwt::sign $key $claims}]
    set result
} -result {1 1 1 1 1}
test jwt-interpreter {key handles cannot cross interpreters or survive interpreter deletion} -body {
    interp create child
    child eval [list set auto_path $auto_path]
    child eval [list source [file join $build_dir pkgIndex.tcl]]
    child eval {package require tink}
    set childKey [child eval {::tink::register_keyset [::tink::jwt::create_private_keyset HS256]}]
    set rejected [catch {::tink::jwt::mac_sign $childKey $claims}]
    interp delete child
    list $rejected [catch {::tink::jwt::mac_sign $childKey $claims}]
} -result {1 1}
set failures $::tcltest::numTests(Failed)
::tcltest::cleanupTests
exit [expr {$failures != 0}]
