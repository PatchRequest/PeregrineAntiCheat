// Peregrine YARA Rules
// Place next to peregrine-tauri.exe or in C:\Peregrine\

rule PeregrineTestCheat {
    meta:
        description = "Peregrine test cheat marker strings"
        severity = "critical"
    strings:
        $marker = "PEREGRINE_CHEAT_MARKER_v1" ascii
        $config = "[cheat_config]" ascii
        $aimbot = "aimbot_fov=" ascii
        $esp    = "esp_enabled=" ascii
    condition:
        $marker and 2 of ($config, $aimbot, $esp)
}
