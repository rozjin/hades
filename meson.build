project('hades', ['cpp', 'c'], version: '0.0.1')
main_sources = files(
    'source/cxx/arch/x86/vmm/syscall.cpp',
    'source/cxx/arch/x86/vmm/vmm.cpp',
    'source/cxx/arch/x86/apic.cpp',
    'source/cxx/arch/x86/core.cpp',
    'source/cxx/arch/x86/irq.cpp',
    'source/cxx/arch/x86/loader.cpp',
    'source/cxx/arch/x86/pit.cpp',
    'source/cxx/arch/x86/hpet.cpp',
    'source/cxx/arch/x86/sched.cpp',
    'source/cxx/arch/x86/signal.cpp',
    'source/cxx/arch/x86/smp.cpp',
    'source/cxx/arch/x86/syscall.cpp',
    'source/cxx/arch/x86/time.cpp',

    'source/cxx/arch/x86/copy.cpp',
    'source/cxx/arch/x86/exception.cpp',

    'source/cxx/driver/net/arp.cpp',
    'source/cxx/driver/net/ip.cpp',
    'source/cxx/driver/net/checksum.cpp',
    'source/cxx/driver/net/e1000.cpp',
    'source/cxx/driver/net/syscall.cpp',

    'source/cxx/driver/tty/tty.cpp',
    'source/cxx/driver/tty/pty.cpp',
    'source/cxx/driver/tty/disciplines.cpp',

    'source/cxx/driver/video/fbdev.cpp',
    'source/cxx/driver/video/vesa.cpp',
    'source/cxx/driver/video/vt.cpp',

    'source/cxx/driver/ahci.cpp',
    'source/cxx/driver/part.cpp',

    'source/cxx/driver/keyboard.cpp',

    'source/cxx/flanterm/flanterm.cpp',
    'source/cxx/flanterm/backends/fb.cpp',

    'source/cxx/fs/dev.cpp',
    'source/cxx/fs/ext2.cpp',
    'source/cxx/fs/rootfs.cpp',
    'source/cxx/fs/syscall.cpp',
    'source/cxx/fs/vfs.cpp',

    'source/cxx/mm/ctx.cpp',
    'source/cxx/mm/mm.cpp',
    'source/cxx/mm/pmm.cpp',
    'source/cxx/mm/vmm.cpp',

    'source/cxx/sys/sched/loader.cpp',
    'source/cxx/sys/sched/sched.cpp',
    'source/cxx/sys/sched/signal.cpp',
    'source/cxx/sys/sched/syscall.cpp',
    'source/cxx/sys/sched/wait.cpp',

    'source/cxx/sys/acpi.cpp',
    'source/cxx/sys/laihost.cpp',
    'source/cxx/sys/pci.cpp',
    'source/cxx/sys/runtime.cpp',

    'source/cxx/util/elf.cpp',
    'source/cxx/util/string.cpp',
    'source/cxx/util/log/log.cpp',

    'source/cxx/entry.cpp'
)
main_includes = include_directories('include')
freestnd_c_hdrs = include_directories('freestnd_c_hdrs', is_system: true)
freestnd_cpp_hdrs = include_directories('freestnd_cpp_hdrs', is_system: true)

nasm_sources = files(
    'source/asm/boot.asm',
    'source/asm/irq.asm',
    'source/asm/syscall.asm'
)

nasm = find_program('nasm')
nasm_gen = generator(nasm, output: '@BASENAME@.o', arguments: ['-f', 'elf64', '-g', '-F', 'dwarf', '@INPUT@', '-o', '@OUTPUT@'])
nasm_objects = nasm_gen.process(nasm_sources)

source_dir = join_paths(meson.project_source_root(), 'source')

ld_script = join_paths(source_dir, 'misc', 'linker.ld')

flags_common = [
	'-ggdb',
	'-O0',
	'-ffreestanding',
    '-nostdinc',
	'-fdiagnostics-color=always',
	'-fno-stack-protector',
	'-fno-omit-frame-pointer',
	'-fno-pic',
	'-mno-sse',
	'-mno-sse2',
	'-mno-mmx',
	'-mno-80387',
	'-mno-red-zone',
	'-m64',
	'-march=x86-64',
	'-mcmodel=kernel'
]

flags_c = [
    '-std=c11'
]

flags_cpp = [
    '-std=gnu++2b',
	'-fno-rtti',
	'-fno-exceptions',
	'-fno-use-cxa-atexit',
]

flags_ld = [
	'-T', ld_script,
    '-nostdlib',
    '-nostartfiles',
    '-nodefaultlibs',
    '-lgcc',
	'-Wl,-z,max-page-size=0x1000',
	'-no-pie'
]

lai_proj = subproject('lai')

lai_sources = lai_proj.get_variable('sources')
lai_includes = lai_proj.get_variable('includes')

make_elf = executable(
    'hades.elf', main_sources, lai_sources,
    nasm_objects,
    include_directories: [main_includes, lai_includes, freestnd_c_hdrs, freestnd_cpp_hdrs],
    link_depends: ld_script, install: true, c_args: flags_common + flags_c, cpp_args: flags_common + flags_cpp, link_args: flags_ld, build_by_default: false)

script_path = join_paths(meson.project_source_root(), 'scripts', 'post.py')
custom_target(
	'hades',
	depends: make_elf,
	input: make_elf,
	output: ['hades.img', 'persist.img'],
	command: [script_path,
		meson.project_name(),
		'-k', make_elf,

		'-s', join_paths(meson.project_source_root(), 'source'),
        '-r', join_paths(meson.project_source_root(), 'user/hbuild'),

		'-b', meson.project_build_root(),
	],
	build_by_default: true,
    build_always_stale: true
)