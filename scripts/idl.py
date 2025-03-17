from lark import Lark, Tree
from lark.visitors import Interpreter

import os
import uuid

class InterfaceGen(Interpreter):
    def write(self, include_file):
        with open(include_file, "w+") as f:
            f.write(self.include)
        
    def emit_include(self, string: str, ident = 0):
        lines = []
        for line in string.splitlines():
            lines.append(((ident + 2) * "    ") + line.rstrip() + "\n")

        self.include = self.include + "".join(lines)
    
    def emit_arguments_struct(self, arguments: dict[str, str]):
        self.emit_include("struct [[gnu::packed]] send_arguments {", 3)
        for name, type in arguments.items():
            self.emit_include(f"{type}{name};", 4)
        
        if len(arguments) > 0:
            self.emit_include(f"send_arguments({",".join(
                [f"{type}{name}" for name, type in arguments.items()]
            )}): {",".join(
                [f"{name}({name})" for name, _ in arguments.items()]
            )} {{}}", 4)
        else:
            self.emit_include("send_arguments() {}", 4)

        self.emit_include("};", 3)

    def parse_type(self, type: str):
        if type == "string":
            return "const char *"
        elif type == "blob":
            return "blob "
        elif type == "void":
            return "void "
        elif type == "ptr":
            return "void *"
        elif type == "size_t":
            return "size_t "
        elif type == "ssize_t":
            return "ssize_t "
        elif type.startswith("u"):
            width = type.strip("u")

            return f"uint{width}_t "
        elif type.startswith("i"):
            width = type.strip("i")

            return f"int{width}_t "

    def interface(self, tree):
        self.include = ""
        self.name = tree.children[1].children[0].value

        self.emit_include("template<typename T>")
        self.emit_include(f"struct {self.name} {{")
        self.emit_include("ipc::port<T> *port;", 1)
        self.emit_include("T *owner;", 1)
        self.visit_children(tree)

        self.emit_include("")
        for child in tree.children[2].children:
            name = child.children[1].children[0].value
            self.emit_include(f"_{name} {name}{{this}};", 1)

        self.emit_include(f"{self.name}(T *owner, ipc::port<T> *port): owner(owner), port(port) {{}}", 1)

        self.emit_include("};")

        with open(os.path.join("include", "ipc", "protocols", "protocol.hpp.in")) as include_template_file:
            include_template = include_template_file.read()

            self.include = include_template.replace("@@INTERFACE@@", self.include)
            self.include = self.include.replace("@@INTERFNAME@@", self.name)
            self.include = self.include.replace("@@INTERFUPPER@@", self.name.upper())


    def message(self, tree):
        is_async = isinstance(tree.children[0], Tree)

        name = tree.children[1].children[0].value
        id = int(uuid.uuid4().hex[:8], base=16)

        self.emit_include(f"struct _{name} {{", 1)
        self.emit_include(f"static constexpr size_t id = {id};", 2)
        if is_async:
            self.emit_include("bool async = true;", 2)
        self.emit_include(f"{self.name} *interf;", 2)
        self.emit_include(f"frg::bound_mem_fn<&T::handle{name.title()}> handler;", 2)

        arguments = self.parse_arguments(tree.children[2])
        return_type = self.parse_return(tree.children[3])

        self.emit_include("private:", 2)
        self.emit_arguments_struct(arguments)

        self.emit_include("public:", 2)

        with open(os.path.join("include", "ipc", "protocols", "function.hpp.in")) as function_include_template_file:
            function_include = function_include_template_file.read()

            function_include = function_include.replace("@@RETURN_TYPE@@", return_type)

            if return_type == "void ":
                function_include = function_include.replace("@@RETURN_STATEMENT@@", "interf->port->getRcvRx()->recv(id);")
                function_include = function_include.replace("@@REPLY_STATEMENT@@", f"""handler({",".join(["do_cancel"] + [f"send_args->{name}" for name, _ in arguments.items()])});
    ipc::header header{{empty::id, sizeof(empty), nullptr}};
    interf->port->getRcvTx()->send(&header, id);""")
            else:
                function_include = function_include.replace("@@RETURN_STATEMENT@@", f"return *({return_type} *) interf->port->getRcvRx()->recv(id)->data;")
                function_include = function_include.replace("@@REPLY_STATEMENT@@", f"""{return_type} res = handler({",".join(["do_cancel"] + [f"send_args->{name}" for name, _ in arguments.items()])});
    protocols::reply<{return_type}> reply{{res}};
    ipc::header header{{protocols::reply<{return_type}>::id, sizeof(protocols::reply<{return_type}>), &reply}};
    interf->port->getRcvTx()->send(&header, id);""")
            
            function_include = function_include.replace("@@interfname@@", self.name)

            self.emit_include(function_include, 3)

        self.emit_include(f"_{name}({self.name} *interf): interf(interf), handler(interf->owner) {{}}", 3)

        self.emit_include("};", 1)

    def parse_arguments(self, tree):
        arguments = {}
        for child in tree.children:
            if isinstance(child, Tree):
                name = child.children[0].children[0].value.strip()
                type = child.children[1].children[0].value.strip()

                if type == "blob":
                    arguments[f"{name}_payload"] = "void *"
                    arguments[f"{name}_len"] = "size_t "
                else:
                    arguments[f"{name}"] = self.parse_type(type)
        
        return arguments

    def parse_return(self, tree):
        return self.parse_type(tree.children[0].children[0].value)

with open("idl_grammar.lark") as grammar_file:
    idl_parser = Lark(grammar_file.read())

    for dir, _, files in os.walk("protocols"):
        for proto_file_name in files:
            if proto_file_name.endswith(".hdl") is False:
                continue

            with open(os.path.join(dir, proto_file_name)) as proto_file:
                parse_result = idl_parser.parse(proto_file.read())

                header_file = os.path.join("include", "ipc", "protocols", proto_file_name.replace(".hdl", ".hpp"))

                interfgen = InterfaceGen()
                interfgen.visit(parse_result)
                interfgen.write(header_file)
            