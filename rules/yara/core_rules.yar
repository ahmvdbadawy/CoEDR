rule Suspicious_API_Calls {
    meta:
        description = "Detects highly suspicious combination of API calls often used in process injection and memory manipulation"
        author = "CoEDR"
        severity = "High"
    strings:
        $virt_alloc = "VirtualAlloc" ascii wide
        $virt_alloc_ex = "VirtualAllocEx" ascii wide
        $write_mem = "WriteProcessMemory" ascii wide
        $create_thread = "CreateRemoteThread" ascii wide
        $queue_apc = "QueueUserAPC" ascii wide
        $nt_unmap = "NtUnmapViewOfSection" ascii wide
        $set_thread_ctx = "SetThreadContext" ascii wide
    condition:
        ($virt_alloc or $virt_alloc_ex) and $write_mem and ($create_thread or $queue_apc or $set_thread_ctx or $nt_unmap)
}

rule Embedded_PE_File {
    meta:
        description = "Detects an embedded portable executable (PE) inside another file or memory region"
        author = "CoEDR"
        severity = "Medium"
    strings:
        $mz = "MZ"
        $dos_stub = "This program cannot be run in DOS mode"
    condition:
        $mz at 0 and $dos_stub
}

rule Obfuscated_PowerShell {
    meta:
        description = "Detects obfuscated PowerShell commands"
        author = "CoEDR"
        severity = "High"
    strings:
        $s1 = "System.Management.Automation.AmsiUtils" ascii wide nocase
        $s2 = "amsiInitFailed" ascii wide nocase
        $s3 = "-EncodedCommand" ascii wide nocase
        $s4 = "-WindowStyle Hidden" ascii wide nocase
        $b64 = /[A-Za-z0-9+\/]{100,}={0,2}/
    condition:
        any of ($s*) or $b64
}

rule Cobalt_Strike_Indicators {
    meta:
        description = "Detects common Cobalt Strike beacon patterns"
        author = "CoEDR"
        severity = "Critical"
    strings:
        $pipe1 = "\\\\.\\pipe\\msagent" ascii wide
        $pipe2 = "\\\\.\\pipe\\mojo" ascii wide
        $pipe3 = "\\\\.\\pipe\\postex" ascii wide
        $user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36" ascii wide
    condition:
        any of ($pipe*) or $user_agent
}
