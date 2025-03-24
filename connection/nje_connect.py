from .connect_interface import iConnect
from extras import njelib


# Currently not used, implement later if things rely on it
class Nje():
    def c_connect(self, host: str):
        rhost = input("RHOST (System to act as): ")
        ohost = input("OHOST (System to connect to): ")
        client = njelib.NJE(rhost, ohost)

        # Check connection
        connected = client.session(host=host, port=175)
        if not connected:
            print("Connection failed.")
            # TODO: make main client end


        return client


    def c_send(self, client):
        pass


    def c_recv(self, client):
        pass


    def c_close(self, client):
        pass