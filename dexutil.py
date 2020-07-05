#!/usr/bin/env python
# coding=utf-8
import sys
import binascii
import hashlib
class dexUtils:
    def __get_hex_from_bytes(self,parm):
        return int.from_bytes(parm,byteorder\
        ='little',signed=False) 
    def __get_bytes_from_int(self,n,size):
        return n.to_bytes(length=size,\
        byteorder='little',signed=False)
    
    #输入是函数名
    def __init__(self,file_name):
        self.__file= open(file_name, 'rb+', True)
        if self.__file == None:
            print('打开文件失败')
            exit(1)
        self.__content=bytearray(self.__file.read())

    #查看基本信息
    def ReadHeaderAndPrintInfo(self):
        self.__file.seek(0)
        
        #切割时候要尾部-1
        i= self.__get_hex_from_bytes(self.__content[0:8])
        if i != 0x3533300a786564:
            print('不是正常dex文件，如果是\
            ，请尝试修复')
        i= self.__get_hex_from_bytes(self.__content[8:0xc])
        print(f'checksum--->{hex(i)}')
        i=self.__get_hex_from_bytes(self.__content[0xc:0x20])
        print(f'signature--->{hex(i)}')
        i=self.__get_hex_from_bytes(self.__content[0x20:0x24])
        print(f'file_size--->{hex(i)}')
        i=self.__get_hex_from_bytes(self.__content[0x24:0x28])
        print(f'header_size--->{hex(i)}')
    #计算checksum函数 
    def __CalculationVar(self,srcByte,vara,varb):
        varA = vara
        varB = varb
        icount = 0
        listAB = []

        while icount < len(srcByte):
            varA = (varA + srcByte[icount])%65521
            varB = (varB + varA)%65521
            icount += 1
        listAB.append(varA)
        listAB.append(varB)
        return listAB
    def __getCheckSum(self,varA,varB):
        Output = (varB << 16) + varA
        return Output
    def getCheckSum(self):
        VarA = 1
        VarB = 0
        flag = 0
        CheckSum = 0
        while True:
            srcBytes = []
            for i in self.__content[0xc:]:
                b=self.__get_bytes_from_int(i,1)
                b = binascii.b2a_hex(b)
                b = str(b,encoding='utf-8')
                b = int(b,16)
                srcBytes.append(b)
            varList = self.__CalculationVar(srcBytes,VarA,VarB)
            VarA = varList[0]
            VarB = varList[1]
            CheckSum = self.__getCheckSum(VarA,VarB)
            return CheckSum   
    #计算signature函数
    def getSignature(self):
        sha1obj=hashlib.sha1()
        sha1obj.update(self.__content[0x20:])
        return self.__get_hex_from_bytes(bytes.fromhex\
        (sha1obj.hexdigest()))
        
    #计算file_size函数
    def getFileSize(self):
        return len(self.__content)

    def fixIt(self):
        #先写入文件大小，signature会根据文件大小的数据变化
        filesize = self.getFileSize()
        self.__content[0x20:0x24]=self.__get_bytes_from_int(\
            self.getFileSize(),4)
        #再写入signature，checksum会根据signature而变化
        self.__content[0xc:0x20]=self.__get_bytes_from_int(\
            self.getSignature(),20)
        #最后写入checksum
        self.__content[8:0xc]=self.__get_bytes_from_int(\
            self.getCheckSum(),4)
        #写入magic
        self.__content[:8]=b'dex\x0a035\x00'
        #写入文件
        self.__file.seek(0)
        self.__file.write(self.__content)
        print('修复成功')

if __name__ == '__main__':
    if len(sys.argv)==3:
        op=sys.argv[1]
        path=sys.argv[2]
        u=dexUtils(path)
        if op=='-p':
            u.ReadHeaderAndPrintInfo()
        if op=='-f':
            u.fixIt()
    else:
        print('参数不正确')
        exit(1)
