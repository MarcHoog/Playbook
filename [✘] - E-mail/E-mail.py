import smtplib, ssl


class Email(object):
    def __init__(self):
        self.port = 465
        self.smpt_server = 'smpt.gmail.com'
        self.sender_email =  "discord.bot.zamyza@gmail.com"
        self.reciever_email =
        self.password = ''
        self.message = """
        Subject: hello there big boi!
        
        """

    def send(self):
        self.password = input("Type your password and press enter: ")

        # Create a secure SSL context
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(self.smpt_server, self.port, context=context) as server:
            server.login(self.sender_email, self.password)
            server.sendmail(self.sender_email,self.reciever_email,self.message)
            # TODO: Send email here