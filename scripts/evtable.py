import os

def read_file(path):
    contents = ""
    with open(path) as f:
        return f.read()

evtable_in = read_file(os.path.join("include", "ipc", "evtable.hpp.in"))

entries = []
with open("evtable") as tbl_file:
    for line in tbl_file:
        values = line.split()
        if not line.strip():
            continue

        name = values[0]
        value = values[1]

        entries.append(f"   constexpr size_t {name} = {value};")
            
evtable = evtable_in
evtable = evtable.replace("@@EVTABLE_ENTRIES@@", "\n".join(entries))

with open(os.path.join("include", "ipc", "evtable.hpp"), "w+") as evtable_hpp:
    evtable_hpp.write(evtable)