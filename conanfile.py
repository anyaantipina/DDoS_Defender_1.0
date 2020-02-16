from conans import ConanFile, tools

class DDoS_DefenderConan(ConanFile):
    name = "DDoS_Defender"
    version = "0.1"
    settings = None
    description = "DDoS Defender"
    url = "None"
    license = "None"
    author = "None"
    topics = None

    def package(self):
        self.copy("*")

    def package_info(self):
        self.cpp_info.libs = tools.collect_libs(self)
