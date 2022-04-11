let g:ale_linters = { 'c': ['cppcheck', 'ccls', 'flawfinder'] }
let g:ale_c_parse_compile_commands = 1
let g:ale_always_make = 1
let g:ale_c_cc_executable = '/usr/bin/gcc'
let g:ale_c_cc_options = '-std=c11 -W -Wall -Wstrict-prototypes -Wmissing-prototypes -DMODULE-D__KERNEL__ -nostdinc -isystem /lib/modules/`uname -r`/build/include -isystem /lib/modules/5.16.14-zen1-1-zen/build/arch/x86/include'

"-isystem /lib/modules/5.16.14-arch1-1/build/arch/x86/include/asm -isystem /lib/modules/5.16.14-arch1-1/build/arch/x86/include -isystem /lib/modules/5.16.14-arch1-1/build/include -isystem /usr/src/linux/include
"-isystem /lib/modules/5.16.14-arch1-1/build/arch/x86/include/generated

"
    "/usr/bin/gcc",
    "-std=c11", "-W", "-Wall", "-Wstrict-prototypes", "-Wmissing-prototypes", "-DMODULE-D__KERNEL__", "-nostdinc",
    "-isystem", "/lib/modules/`uname -r`/build/include", "-isystem", "/lib/modules/5.16.14-zen1-1-zen/build/arch/x86/include"
