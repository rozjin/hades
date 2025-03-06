import os

def read_file(path):
    contents = ""
    with open(path) as f:
        return f.read()

dtable_in = read_file(os.path.join("include", "driver", "dtable.hpp.in"))
majtable_in = read_file(os.path.join("include", "driver", "majtable.hpp.in"))

entries = []
majors = []
with open("dtable") as tbl_file:
    for line in tbl_file:
        values = line.split()
        if not line.strip():
            continue

        bus = values[0]
        if bus == "pci":
            vend, dev, cls, subcls, progif = ["MATCH_ANY" if x == "?" else f"{int(x, base=16):#x}" for x in values[1:6]]

            matcher = values[6]
            major = int(values[7], base=16)

            name = values[8]

            entries.append(f"        {{ .match_data = {{{vend}, {dev}, {cls}, {subcls}, {progif}}}, .major = majors::{name}, .matcher = new {matcher}()}}")
            majors.append(f"        constexpr size_t {name} = {major};")
        elif bus == "none":
            matcher = values[1]
            major = int(values[2], base=16)
            name = values[3]

            entries.append(f"        {{ .match_data = {{0}}, .major=majors::{name}, .matcher = new {matcher}()}}")
            majors.append(f"        constexpr size_t {name} = {major};")
        elif bus == "major":
            major = int(values[1], base=16)
            name = values[2]

            majors.append(f"        constexpr size_t {name} = {major};")

dtable = dtable_in
majtable = majtable_in

dtable = dtable.replace("@@DTABLE_ENTRIES@@", ",\n".join(entries))
majtable = majtable.replace("@@DTABLE_MAJORS@@", "\n".join(majors))

with open(os.path.join("include", "driver", "dtable.hpp"), "w+") as dtable_hpp:
    dtable_hpp.write(dtable)

with open(os.path.join("include", "driver", "majtable.hpp"), "w+") as majtable_hpp:
    majtable_hpp.write(majtable)