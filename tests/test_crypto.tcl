#
# test_crypto.tcl - Test script for TclTLS v2.0 with merged crypto commands
#
# Usage: tclsh test_crypto.tcl
#   Or if the package is not installed:
#     tclsh test_crypto.tcl <path_to_build_dir>
#

proc log {msg} {
    puts "  $msg"
}

proc pass {name} {
    puts "PASS: $name"
}

proc fail {name msg} {
    puts "FAIL: $name - $msg"
    incr ::failures
}

proc test {name body} {
    if {[catch {uplevel 1 $body} err]} {
        fail $name $err
    } else {
        pass $name
    }
}

set failures 0

# Load package
if {$argc > 0} {
    set builddir [lindex $argv 0]
    lappend auto_path $builddir
}

puts "============================================"
puts " TclTLS v2.0 + Crypto Merge Test"
puts "============================================"
puts ""

if {[catch {package require tls} ver]} {
    puts "ERROR: Cannot load tls package: $ver"
    puts "  Make sure the package is built and provide the build dir as argument."
    exit 1
}

puts "Loaded tls package version: $ver"
puts ""

# ---- Section 1: Basic TLS commands (existing) ----
puts "--- Section 1: Existing TLS Commands ---"

test "tls::version returns string" {
    set v [::tls::version]
    if {$v eq ""} {error "empty version string"}
    log "OpenSSL version: $v"
}

test "tls::protocols returns list" {
    set p [::tls::protocols]
    if {[llength $p] == 0} {error "empty protocols list"}
    log "Protocols: $p"
}

test "tls::ciphers returns list" {
    set c [::tls::ciphers]
    if {[llength $c] == 0} {error "empty ciphers list"}
    log "Cipher count: [llength $c]"
}

puts ""

# ---- Section 2: Random ----
puts "--- Section 2: ::tls::random ---"

test "tls::random generates bytes" {
    set r [::tls::random 16]
    if {[string length $r] != 16} {error "expected 16 bytes, got [string length $r]"}
    log "Generated 16 random bytes OK"
}

test "tls::random 32 bytes" {
    set r [::tls::random 32]
    if {[string length $r] != 32} {error "expected 32 bytes, got [string length $r]"}
    log "Generated 32 random bytes OK"
}

test "tls::random -private 16" {
    set r [::tls::random -private 16]
    if {[string length $r] != 16} {error "expected 16 bytes, got [string length $r]"}
    log "Generated 16 private random bytes OK"
}

test "tls::random 0 bytes" {
    set r [::tls::random 0]
    if {[string length $r] != 0} {error "expected 0 bytes"}
    log "Zero-length random OK"
}

puts ""

# ---- Section 3: Message Digest ----
puts "--- Section 3: ::tls::md / ::tls::digest ---"

test "tls::md sha256 of empty string" {
    set h [::tls::md sha256 -data ""]
    # SHA-256 of empty string
    set expected "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    if {$h ne $expected} {error "got $h, expected $expected"}
    log "SHA-256('') = $h"
}

test "tls::md sha256 of hello" {
    set h [::tls::md sha256 -data "hello"]
    set expected "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    if {$h ne $expected} {error "got $h, expected $expected"}
    log "SHA-256('hello') = $h"
}

test "tls::md sha1 of hello" {
    set h [::tls::md sha1 -data "hello"]
    set expected "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
    if {$h ne $expected} {error "got $h, expected $expected"}
    log "SHA-1('hello') = $h"
}

test "tls::md md5 of hello" {
    set h [::tls::md md5 -data "hello"]
    set expected "5d41402abc4b2a76b9719d911017c592"
    if {$h ne $expected} {error "got $h, expected $expected"}
    log "MD5('hello') = $h"
}

test "tls::digest sha256 (alias)" {
    set h [::tls::digest sha256 -data "test"]
    if {[string length $h] != 64} {error "unexpected length [string length $h]"}
    log "SHA-256('test') = $h"
}

test "tls::md sha256 -bin returns binary" {
    set h [::tls::md sha256 -bin -data "hello"]
    if {[string length $h] != 32} {error "expected 32 bytes, got [string length $h]"}
    log "SHA-256 binary output: 32 bytes OK"
}

puts ""

# ---- Section 4: HMAC ----
puts "--- Section 4: ::tls::hmac ---"

test "tls::hmac sha256" {
    set key "secret"
    set h [::tls::hmac sha256 -key $key -data "hello"]
    if {[string length $h] != 64} {error "unexpected hex length [string length $h]"}
    log "HMAC-SHA256('hello', 'secret') = $h"
}

test "tls::hmac sha1" {
    set key "key"
    set h [::tls::hmac sha1 -key $key -data "message"]
    if {[string length $h] != 40} {error "unexpected hex length [string length $h]"}
    log "HMAC-SHA1('message', 'key') = $h"
}

puts ""

# ---- Section 5: Encryption/Decryption ----
puts "--- Section 5: ::tls::encrypt / ::tls::decrypt ---"

test "tls::encrypt and decrypt aes-128-cbc" {
    set key [string repeat \x00 16]
    set iv  [string repeat \x00 16]
    set plaintext "Hello, TclTLS crypto world!!!"

    set encrypted [::tls::encrypt -cipher aes-128-cbc -key $key -iv $iv -data $plaintext]
    if {$encrypted eq $plaintext} {error "encryption produced plaintext"}

    set decrypted [::tls::decrypt -cipher aes-128-cbc -key $key -iv $iv -data $encrypted]
    if {$decrypted ne $plaintext} {error "decryption mismatch: got '$decrypted'"}
    log "AES-128-CBC encrypt/decrypt roundtrip OK"
}

test "tls::encrypt and decrypt aes-256-cbc" {
    set key [string repeat \x01 32]
    set iv  [string repeat \x02 16]
    set plaintext "Testing AES-256-CBC encryption"

    set encrypted [::tls::encrypt -cipher aes-256-cbc -key $key -iv $iv -data $plaintext]
    set decrypted [::tls::decrypt -cipher aes-256-cbc -key $key -iv $iv -data $encrypted]
    if {$decrypted ne $plaintext} {error "decryption mismatch"}
    log "AES-256-CBC encrypt/decrypt roundtrip OK"
}

puts ""

# ---- Section 6: KDF ----
puts "--- Section 6: ::tls::pbkdf2 / ::tls::hkdf / ::tls::scrypt ---"

test "tls::pbkdf2 derives key" {
    set dk [::tls::pbkdf2 -digest sha256 -password "password" -salt "salt" -iterations 1000 -size 32]
    if {[string length $dk] != 32} {error "expected 32 bytes, got [string length $dk]"}
    log "PBKDF2-SHA256 derived 32 bytes OK"
}

test "tls::hkdf derives key" {
    set dk [::tls::hkdf -digest sha256 -key "input_key_material" -salt "salt" -info "context" -size 32]
    if {[string length $dk] != 32} {error "expected 32 bytes, got [string length $dk]"}
    log "HKDF-SHA256 derived 32 bytes OK"
}

test "tls::scrypt derives key" {
    set dk [::tls::scrypt -password "password" -salt "NaCl" -N 1024 -r 8 -p 1 -size 64]
    if {[string length $dk] != 64} {error "expected 64 bytes, got [string length $dk]"}
    log "scrypt derived 64 bytes OK"
}

puts ""

# ---- Section 7: Info commands ----
puts "--- Section 7: Info Commands ---"

test "tls::digests returns list" {
    set d [::tls::digests]
    if {[llength $d] == 0} {error "empty digests list"}
    log "Available digests: [llength $d] ([lrange $d 0 4] ...)"
}

test "tls::cipher info for aes-256-cbc" {
    set info [::tls::cipher aes-256-cbc]
    if {[llength $info] == 0} {error "empty cipher info"}
    log "Cipher info keys: [dict keys $info]"
}

test "tls::macs returns list" {
    set m [::tls::macs]
    if {[llength $m] == 0} {error "empty macs list"}
    log "Available MACs: $m"
}

test "tls::kdfs returns list" {
    set k [::tls::kdfs]
    if {[llength $k] == 0} {error "empty kdfs list"}
    log "Available KDFs: $k"
}

test "tls::pkeys returns list" {
    set p [::tls::pkeys]
    if {[llength $p] == 0} {error "empty pkeys list"}
    log "Available pkey methods: [llength $p]"
}

puts ""

# ---- Section 8: Command-based digest ----
puts "--- Section 8: Command-based Digest ---"

test "tls::md command interface" {
    set cmd [::tls::md sha256 -command mydigest]
    $cmd update "hello"
    $cmd update " world"
    set h [$cmd finalize]
    set expected [::tls::md sha256 -data "hello world"]
    if {$h ne $expected} {error "command digest mismatch: $h vs $expected"}
    log "Command-based SHA-256 matches one-shot: OK"
}

puts ""

# ---- Summary ----
puts "============================================"
if {$failures == 0} {
    puts " ALL TESTS PASSED"
} else {
    puts " $failures TEST(S) FAILED"
}
puts "============================================"

exit $failures

