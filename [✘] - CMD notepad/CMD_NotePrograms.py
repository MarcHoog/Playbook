class CommandSwitcher(object):
    def __init__(self):
        self.command_argument = []

    def show_all(self):
        print(f' I am /a argument is')

    def show_catagory(self):
        print(f' I am /s argument is: {self.command_argument}')

    def handler_input(self, argument):
        self.command_argument = argument[1:]

        switcher = {
            '/a': self.show_all,
            '/s': self.show_catagory
        }
        try:
            func = switcher.get(argument[0])
            func()
        except (IndexError, TypeError):
            print(f'[!]Error: Wrong argument')

    def get_input(self):
        self.handler_input(input(':  ').split())


if __name__ == '__main__':
    program = CommandSwitcher()
    while True:
        program.get_input()
