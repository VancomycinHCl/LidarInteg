from scapy.all import *
from scapy.layers.inet import UDP


class PcapFile():
    def __init__(self,file):
        self.fp = rdpcap(file)

class Package(PcapFile):
    def __init__(self,file):
        super(Package, self).__init__(file)
        self._timestamp = []
        self._payload = []
        self.ReadPcapUDP()

    def ReadPcapUDP(self):
        #count = 100
        for i in self.fp:
            self._timestamp.append(float(i.time))
            self._payload.append(bytes(i[UDP].payload))
            #i.show()
            #if count == 1:
                #break
            #count -= 1


    def WritePcapToBinAsDump(self,wkDict):
        for i in range(len(self._timestamp)):
            fileName = wkDict + str(i) + ".dump"
            file = open(file=fileName,mode="wb+")
            file.write(self._payload[i])
            file.close()
    def GetTimeStamp(self):
        return self._timestamp

    def SetTimeStamp(self,UTCTimeIn):
        self._timestamp = UTCTimeIn
        return

    def GetPayload(self):
        return self._payload

    def SetPayload(self,UDPBytesIn):
        self._payload = UDPBytesIn
        return


if __name__ == "__main__":
    a1 = Package("target2800.pcap")
    t1 = a1.GetPayload()
    for i in t1:
        pass
        #print(i)
    a1.WritePcapToBinAsDump("../RawLidarBin/RawLidarBin")