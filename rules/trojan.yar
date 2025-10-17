rule trojan_test {
    meta:
        author = "Huy"
        family = "Trojan"
    strings:
        $a = "CreateRemoteThread" ascii
        $b = "VirtualAlloc" ascii
    condition:
        any of them
}
