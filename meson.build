project('hades', ['cpp', 'c'], version: '0.0.1')
main_sources = files(
    'source/cxx/arch/x86/vmm/syscall.cpp',
    'source/cxx/arch/x86/vmm/vmm.cpp',
    'source/cxx/arch/x86/bus/pci.cpp',
    'source/cxx/arch/x86/apic.cpp',
    'source/cxx/arch/x86/core.cpp',
    'source/cxx/arch/x86/irq.cpp',
    'source/cxx/arch/x86/loader.cpp',
    'source/cxx/arch/x86/pit.cpp',
    'source/cxx/arch/x86/hpet.cpp',
    'source/cxx/arch/x86/sched.cpp',
    'source/cxx/arch/x86/signal.cpp',
    'source/cxx/arch/x86/smp.cpp',
    'source/cxx/arch/x86/ssp.cpp',
    'source/cxx/arch/x86/syscall.cpp',
    'source/cxx/arch/x86/time.cpp',

    'source/cxx/arch/x86/copy.cpp',
    'source/cxx/arch/x86/exception.cpp',

    'source/cxx/driver/bus/pci.cpp',

    'source/cxx/driver/pci/ahci.cpp',
    'source/cxx/driver/pci/net.cpp',

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

    'source/cxx/driver/dtable.cpp',

    'source/cxx/driver/ahci.cpp',
    'source/cxx/driver/part.cpp',

    'source/cxx/driver/keyboard.cpp',

    'source/cxx/flanterm/flanterm.cpp',
    'source/cxx/flanterm/backends/fb.cpp',

    'source/cxx/fs/cache.cpp',
    'source/cxx/fs/dev.cpp',
    'source/cxx/fs/ext2.cpp',
    'source/cxx/fs/rootfs.cpp',
    'source/cxx/fs/syscall.cpp',
    'source/cxx/fs/vfs.cpp',

    'source/cxx/ipc/wire.cpp',
    'source/cxx/ipc/port.cpp',
    'source/cxx/ipc/link.cpp',

    'source/cxx/mm/ctx.cpp',
    'source/cxx/mm/mm.cpp',
    'source/cxx/mm/pmm.cpp',
    'source/cxx/mm/vmm.cpp',

    'source/cxx/sys/sched/management.cpp',
    'source/cxx/sys/sched/sched.cpp',
    'source/cxx/sys/sched/signal.cpp',
    'source/cxx/sys/sched/syscall.cpp',

    'source/cxx/sys/acpi.cpp',
    'source/cxx/sys/laihost.cpp',
    'source/cxx/sys/runtime.cpp',
    'source/cxx/sys/ubsan.cpp',

    'source/cxx/util/elf.cpp',
    'source/cxx/util/string.cpp',
    'source/cxx/util/log/log.cpp',

    'source/cxx/entry.cpp'
)
main_includes = include_directories('include')
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
    '-m64',
	'-march=x86-64',
    '-mcmodel=kernel',
	'-fno-omit-frame-pointer',
    '-fno-pic',
	'-ffreestanding',
	'-fstack-protector',
	'-fdiagnostics-color=always',

    '-nostdlib',
	'-mno-sse',
	'-mno-sse2',
	'-mno-mmx',
	'-mno-80387',
	'-mno-red-zone',

	'-ggdb',
]

flags_c = [
    '-std=c11'
]

flags_cpp = [
    '-std=gnu++2c',
	'-fno-rtti',
	'-fno-exceptions',
	'-fuse-cxa-atexit',
]

flags_ld = [
	'-T', ld_script,
    '-nostdlib',
    '-mcmodel=kernel',
    '-fno-pic',
    '-no-pie',
    '-Wl,-z,max-page-size=0x1000,-n',
    '-lgcc'
]

crtbegin_obj_command = run_command(meson.get_compiler('cpp'),  flags_common + flags_c, '-print-file-name=crtbegin.o')
crtbegin_obj = crtbegin_obj_command.stdout().strip()

crtend_obj_command = run_command(meson.get_compiler('cpp'),  flags_common + flags_c, '-print-file-name=crtend.o')
crtend_obj = crtend_obj_command.stdout().strip()

crt_files = files(crtbegin_obj, crtend_obj)

add_global_arguments(flags_common + flags_c, language: 'c')
add_global_link_arguments(flags_ld, language: 'c')
add_global_arguments(flags_common + flags_cpp, language: 'cpp')
add_global_link_arguments(flags_ld, language: 'cpp')

lai_proj = subproject('lai')
lai_dependency = lai_proj.get_variable('dependency')

make_elf = executable(
    'hades.elf', main_sources,
    nasm_objects, objects: crt_files,
    dependencies: [lai_dependency],
    include_directories: [main_includes, freestnd_cpp_hdrs],
    link_depends: ld_script, install: true, build_by_default: false)

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