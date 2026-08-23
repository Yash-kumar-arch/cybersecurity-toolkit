class Plugin():
    def analyze(self,response):
        raise NotImplementedError

    def get_paths(self):
        return []