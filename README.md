#Curso Practical Malware Analysis
#Para usar este plug-in, salve o código em um arquivo com a extensão ".py" e carregue-o no IDA usando o menu "File->Script file".
#É importante observar que para usar o plugin IDA python, você precisa ter o IDA Pro com suporte python instalado.
#Abaixo o plugin escrito em python para o depurador IDA que imprime o endereço e a instrução de cada função atual do malware.

import idaapi

class MyPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "Este é um plugin IDA Python"
    help = "Este plug-in imprime o endereço e a instrução de cada instrução na função atual"
    wanted_name = "Meu plugin"
    wanted_hotkey = "Ctrl-Alt-P"

    def init(self):
        idaapi.msg("Meu Plugin foi inicializado\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        func = idaapi.get_func(idaapi.get_screen_ea())
        if not func:
            idaapi.msg("Posicione o cursor dentro de uma função\n")
            return
        
        for head in idaapi.heads(func.startEA, func.endEA):
            idaapi.msg("0x%x: %s\n" % (head, idaapi.get_disasm(head)))

    def term(self):
        idaapi.msg("Meu plug-in foi encerrado\n")

def PLUGIN_ENTRY():
    return MyPlugin()
