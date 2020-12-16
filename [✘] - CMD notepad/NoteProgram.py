from CMD_NotePrograms import CommandSwitcher


class CMDNote(object):
    def __init__(self):
        self.version = 0.1



if __name__ == '__main__':
    program = CommandSwitcher()
    program.get_input()
