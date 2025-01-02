#!/usr/bin/python3

import argparse
import os
import subprocess
import shutil
from pathlib import Path

parser = argparse.ArgumentParser()

parser.add_argument("name", help = "Project name")
parser.add_argument("-s", "--source", help = "The source meson folder for the project.", required = True)
parser.add_argument("-r", "--hbuild", help = "The hbuild folder.", required = True)
parser.add_argument("-b", "--build", help = "The meson build folder.", required = True)
parser.add_argument("-k", "--kernel", help = "Kernel ELF file path.", required = True)
args = parser.parse_args()

source_dir = Path(args.source).resolve()
build_dir = Path(args.build).resolve()
scripts_dir = Path(source_dir, "..", "scripts").resolve()
sysroot_dir = Path(args.hbuild, "system_files").resolve()
base_dir = Path(source_dir, "..", "base_files").resolve()
mount_dir = Path("/mnt", f"{args.name}").resolve()

kernel_path = Path(args.kernel).resolve()
image_path = Path(build_dir, f"{args.name}.img").resolve()
vmdk_path = Path(build_dir, f"{args.name}.vmdk").resolve()

qcow2_path = Path(source_dir, "..", "hades.qcow2").resolve()

def do_boot_disk():
    image_path.touch(exist_ok = True)

    subprocess.run(["dd", "if=/dev/zero", "bs=4M", "count=128", f"of={str(image_path)}"])

    subprocess.run(["parted", "-s", str(image_path), "mklabel", "msdos"])
    subprocess.run(["parted", "-s", str(image_path), "mkpart", "primary", "2048s", '100%'])

    subprocess.run(["echfs-utils", "-m", "-p0", str(image_path), "quick-format", "512"])
    subprocess.run(["echfs-utils", "-m", "-p0", str(image_path), "import", str(Path(source_dir, "misc", "limine.cfg").resolve()), "limine.cfg"])
    subprocess.run(["echfs-utils", "-m", "-p0", str(image_path), "import", str(Path(source_dir, "misc", "limine.sys").resolve()), "limine.sys"])

    """
    TODO:

        if [[ -d ${MESON_SOURCE_DIR}/init && ! -L ${MESON_SOURCE_DIR}/init ]]; then
            ls ${MESON_SOURCE_DIR}/init | cpio -ov > ${MESON_BUILD_DIR}/initrd
        fi
    """

    subprocess.run(["echfs-utils", "-m", "-p0", str(image_path), "import", str(kernel_path), kernel_path.name])
def do_limine_install():
    subprocess.run([Path(source_dir, "misc", "limine-install").resolve(), str(image_path)])

def do_sysroot():
    for root, dirs, files in os.walk(mount_dir):
        for f in files:
            os.unlink(os.path.join(root, f))
        for d in dirs:
            shutil.rmtree(os.path.join(root, d))

    shutil.copytree(sysroot_dir, mount_dir, dirs_exist_ok=True)
    shutil.copytree(base_dir, mount_dir, dirs_exist_ok=True)

def do_vmdk():
    subprocess.run(["qemu-img", "convert", "-O", "vmdk", str(image_path), str(vmdk_path)])

do_boot_disk()
do_limine_install()
do_sysroot()
# do_vmdk()