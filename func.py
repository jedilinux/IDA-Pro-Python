import idaapi

class MyPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "Este é um plugin IDA Python"
    help = "Este plugin imprime o endereço e a instrução de cada instrução na função atual\n"
    wanted_name = "My Plugin"
    wanted_hotkey = "Ctrl-Alt-P"

    def init(self):
        idaapi.msg("My Plugin has been initialized\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        func = idaapi.get_func(idaapi.get_screen_ea())
        if not func:
            idaapi.msg("Por favor, posicione o cursor dentro de uma função\n")
            return
        
        for head in idaapi.heads(func.startEA, func.endEA):
            idaapi.msg("0x%x: %s\n" % (head, idaapi.get_disasm(head)))

    def term(self):
        idaapi.msg("encerrado\n")

def PLUGIN_ENTRY():
    return MyPlugin()
