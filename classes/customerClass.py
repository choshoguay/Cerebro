
class customer:
    def __init__(self, customer_name=None, customer_site=None):
        self.customer_name = customer_name
        self.customer_site = customer_site

    def get_customer_name(self):
        return self.customer_name
    
    def get_customer_site(self):
        return self.customer_site
    
    def set_customer_name(self, customer_name):
        self.customer_name = customer_name

    def set_customer_site(self, customer_site):
        self.customer_site = customer_site


    