from abc import ABC, abstractmethod

class iConnect(ABC):
    @abstractmethod
    def c_connect(self, host: str):
        pass


    @abstractmethod
    def c_send(self, client):
        pass


    @abstractmethod
    def c_recv(self, client):
        pass


    @abstractmethod
    def c_close(self, client):
        pass