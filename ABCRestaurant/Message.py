class Message:
    count_id = 0
    def __init__(self, first_name, last_name, email, subject, enquiry):
        Message.count_id += 1
        self.__message_id = Message.count_id
        self.__first_name = first_name
        self.__last_name = last_name
        self.__email = email
        self.__subject = subject
        self.__enquiry = enquiry

    def get_message_id(self):
        return self.__message_id
    def get_first_name(self):
        return self.__first_name
    def get_last_name(self):
        return self.__last_name
    def get_email(self):
        return self.__email
    def get_subject(self):
        return self.__subject
    def get_enquiry(self):
        return self.__enquiry

    def set_message_id(self, message_id):
        self.__message_id = message_id
    def set_first_name(self, first_name):
        self.__first_name = first_name
    def set_last_name(self, last_name):
        self.__last_name = last_name
    def set_email(self, email):
        self.__email = email
    def set_subject(self, subject):
        self.__subject = subject
    def set_enquiry(self, enquiry):
        self.__enquiry = enquiry
