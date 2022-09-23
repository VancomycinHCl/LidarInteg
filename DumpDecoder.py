from PcapDecoder import *
import os
import ctypes
import numpy as np
import matplotlib.pyplot as plt

class LidarPoints(Package):
    def __init__(self,pcapFile):
        super(LidarPoints, self).__init__(pcapFile)
        self._frames = []

    def Payload2Points(self):
        count = 0
        for i in self._payload:
            print(i)
            print(i[114])
            if count==100:
                break
            count+=1
            pass

class LidarVideo():
    def __init__(self, file="target2800.pcap", frameQuantites=1, radius_limit=500, intensity_limit=20):
        self.frames = []
        self.file = file
        self.dumpPtr = DumpFromPcapDecoder(self.file)
        for i in range(0,frameQuantites,1):
            self.frames.append(LidarFrame(file=self.file,dumpPtr=self.dumpPtr,radius_limit=radius_limit,intensity_limit=intensity_limit))
            self.frames[-1].ReadDumpToFrame()

class LidarFrame():
    def __init__(self,dumpPtr=None,file="target2800.pcap",frameNum=1,radius_limit=500,intensity_limit=20):
        self.packets = []
        self.PACKET_NUM = 630
        self.FILENAME = file
        self.ReadPcapAsDumpPtr(dumpPtr=dumpPtr)
        self.files = self.pcapFile.payloads
        self.file = self.files[0]
        self.pcapFile.paylod = self.files[0]
        self.frameId = frameNum-1
        self.radiusLimit = radius_limit
        self.intensity = intensity_limit
    def ReadPcapAsDumpPtr(self,dumpPtr):
        if type(dumpPtr) == DumpFromPcapDecoder:
            self.pcapFile = dumpPtr
        else:
            self.pcapFile = DumpFromPcapDecoder(self.FILENAME)
    def ReadDumpToFrame(self):
        for i in range(self.frameId*self.PACKET_NUM,self.frameId*self.PACKET_NUM+630):
            file = self.files[i]
            self.pcapFile.payload = file
            packet = LidarPackage(radius_limit=self.radiusLimit,intensity_limit=self.intensity,fileIn=self.pcapFile)
            packet.readDump()
            if packet.blocks != [] or packet.blocks != None:
                self.packets.append(ctypes.cast(id(packet),ctypes.py_object).value)
            else:
                pass

class DumpFile():
    def __init__(self,filepath):
        self.filePath = filepath
        self.file = open(self.filePath,"rb")
        self.size = os.path.getsize(self.filePath)
        self.payload = self.file.read(self.size)
        self.HEAD_LEN = 32
        self.BLOCK_HEAD_LEN = 2
        self.BLOCK_LEN = 47
        self.POINT_HEAD_LEN = 2
        self.POINT_LEN = 9
    def __del__(self):
        self.file.close()

class DumpFromPcapDecoder(Package):
    def __init__(self,filepath):
        super(DumpFromPcapDecoder, self).__init__(filepath)
        self.filePath = filepath
        self.payloads = self._payload
        self.payload = None
        self.HEAD_LEN = 32
        self.BLOCK_HEAD_LEN = 2
        self.BLOCK_LEN = 47
        self.POINT_HEAD_LEN = 2
        self.POINT_LEN = 9

class LidarPackage():
    def __init__(self,fileIn,radius_limit=50,intensity_limit=20):
        self.timestamp = None
        self.packet_psn = None
        self.blocks = []
        self.RADIUS_LIMIT = radius_limit
        self.INTENSITY_LIMIT = intensity_limit
        self.file = fileIn

    def readDump(self,filePath=""):
        #file = DumpFile(filePath)
        file = self.file
        self.timestamp = self.getTimeFromDump(file)
        self.packet_psn = self.getPktPsn(file)
        print(self.timestamp,self.packet_psn)
        for i in range(0,25):
            a = LidarBlock()
            a.getBlockTime(dumpPtr=file,blockId=i+1)
            for j in range(0,5):
                b = LidarPoint()
                b.getPointInfo(dumpPtr=file,blockId=i+1,pointId=j+1)
                flag = self.pointsFilter(b)
                if flag==True:
                    a.points.append(ctypes.cast(id(b),ctypes.py_object).value)
                else:
                    pass
            if a.points==[]:
                pass
            else:
                self.blocks.append(ctypes.cast(id(a),ctypes.py_object).value)


    def getTimeFromDump(self,dumpPtr):
        timestamp_s = dumpPtr.payload[10:16:1]
        timestamp_u = dumpPtr.payload[16:20:1]
        timestamp_s = int.from_bytes(timestamp_s, byteorder='big', signed=False)
        timestamp_u = int.from_bytes(timestamp_u, byteorder='big', signed=False)
        return timestamp_s + timestamp_u * 1e-6

    def getPktPsn(self,dumpPtr):
        pkt_psn = dumpPtr.payload[4:6:1]
        pkt_psn = int.from_bytes(pkt_psn,byteorder='big',signed=False)
        return pkt_psn

    def pointsFilter(self,pointInstanse):
        radius = pointInstanse.radius
        intensity = pointInstanse.intensity
        #print(radius,intensity)
        if (radius < self.RADIUS_LIMIT and intensity > self.INTENSITY_LIMIT):
            return True
        else:
            return False

class LidarBlock():
    def __init__(self):
        self.blockID = None
        self.timeOffset = None
        self.points = []

    def getBlockTime(self,dumpPtr,blockId):
        fileOffset = dumpPtr.HEAD_LEN + dumpPtr.BLOCK_LEN * (blockId-1)
        blockTimeOffset = dumpPtr.payload[fileOffset:fileOffset+1:1]
        return blockTimeOffset
        #print(int.from_bytes(blockTimeOffset,'big',signed=False))

class LidarPoint():
    def __init__(self):
        self.channel = None
        self.radius = None
        self.elevation = None
        self.azimuth = None
        self.intensity = None
        self.x_cord = None
        self.y_cord = None
        self.z_cord = None

    def getPointInfo(self,dumpPtr,blockId,pointId):
        fileOffset = dumpPtr.HEAD_LEN + dumpPtr.BLOCK_LEN * (blockId-1) + dumpPtr.BLOCK_HEAD_LEN + dumpPtr.POINT_LEN*(pointId-1)
        radius = dumpPtr.payload[fileOffset:fileOffset+2:1]
        radius = int.from_bytes(radius,'big',signed=False) / 200
        elevation = dumpPtr.payload[fileOffset+2:fileOffset+4:1]
        elevation = (int.from_bytes(elevation,'big',signed=False) - 32768) * 0.01
        azimuth = dumpPtr.payload[fileOffset+4:fileOffset+6:1]
        azimuth = (int.from_bytes(azimuth,'big',signed=False) - 32768) * 0.01
        intensity = dumpPtr.payload[fileOffset+6:fileOffset+7:1]
        intensity = int.from_bytes(intensity,'big',signed=False)
        self.channel = pointId
        self.radius = radius
        self.elevation = elevation
        self.azimuth = azimuth
        self.intensity = intensity
        #print(radius,elevation,azimuth,intensity)
        (self.x_cord,self.y_cord,self.z_cord)=self.AssumpCartesianCoordinate(radius,elevation,azimuth)
        return

    def AssumpCartesianCoordinate(self,radius,elevation,azimuth):
        x_cord = radius * np.cos(elevation/360*2*np.pi) * np.cos(azimuth/360*2*np.pi)
        y_cord = radius * np.cos(elevation/360*2*np.pi) * np.sin(azimuth/360*2*np.pi)
        z_cord = radius * np.sin(elevation/360*2*np.pi)
        return (x_cord,y_cord,z_cord)

def testBench(x,y,z,intensity):
    fig = plt.figure()
    ax = plt.axes(projection='3d')
    plotSet = ax.scatter(x, y, z, c=intensity, s=1, cmap='jet', vmin=0, vmax=255)
    ax.set_zlim((-13, 40))
    ax.get_xaxis().set_visible(False)
    ax.get_yaxis().set_visible(False)
    ax.get_zaxis().set_visible(False)
    fig.colorbar(plotSet, label="intensity")
    plt.show()

if __name__ == "__main__":
    #a = LidarFrame(file="target2800.pcap")
    #a.ReadDumpToFrame()
    #a = LidarPackage(radius_limit=1000,intensity_limit=50)
    #a.readDump(filePath="../RawLidarBin/RawLidarBin75.dump")
    a = LidarVideo(file="target2800.pcap",frameQuantites=150,radius_limit=50,intensity_limit=200)
    x = []
    y = []
    z = []
    i = []
    a1 = a.frames[0]
    for packet in a1.packets:
        for block in packet.blocks:
            for point in block.points:
                print(point.radius,"\t",point.intensity,'\t',point.elevation,'\t',point.azimuth,'\t',point.x_cord,'\t',point.y_cord,'\t',point.z_cord)
                x.append(point.x_cord)
                y.append(point.y_cord)
                z.append(point.z_cord)
                i.append(point.intensity)
    testBench(x,y,z,i)
    #a = LidarPoints("target2800.pcap")
    #a.Payload2Points()