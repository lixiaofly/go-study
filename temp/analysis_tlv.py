
    #解析扩展后的tlv格式
    def read_file(self,filename):
        with open(filename,'rb') as fopen:
            return fopen.read()
    def read_str_file(self,filename):
        with open(filename,'r') as fopen:
            return fopen.read()
    def analysis_new_tlv(self,StrBuf,tlvData):
        id, shortData, flag, length = struct.unpack("2BHI", StrBuf[0:8])
        if id == 203:
            self.analysis_file(StrBuf[8:length],length - shortData,tlvData)
        return StrBuf[length:]
    
    #解析原始tlv格式    
    def analysis_old_tlv(self,StrBuf,tlvData):
        id, shortData, typeAndLength = struct.unpack("2BH", StrBuf[0:4])
        length = typeAndLength >> 4
        if id == 3:
            self.analysis_tuple(StrBuf[4:44],tlvData)
        elif id == 11:
            self.analysis_host(StrBuf[4:length],length - shortData,tlvData)
        elif id == 12:
            self.analysis_url(StrBuf[4:length],length - shortData,tlvData)
        
        return StrBuf[length:]
        
    def analysis_tlv(self,fileName):
        StrBuf = self.read_file(self.xdr_decompress_dir + fileName)
        StrLen = len(StrBuf)
        #解析头
        while len(StrBuf) > 0:
            Id, ShortData, Type, Length = struct.unpack("2BHI", StrBuf[0:8])
            StrBuf = StrBuf[8:]
            tlvData = TlvData()
            while len(StrBuf) > 0:
                
                Id, ShortData, TypeAndLength = struct.unpack("2BH", StrBuf[0:4]) 
                if Id == 0:
                    break
                if TypeAndLength&0x1 == 1:
                    StrBuf = self.analysis_new_tlv(StrBuf,tlvData)
                else:
                    StrBuf = self.analysis_old_tlv(StrBuf,tlvData)
            self.saveData(tlvData)
            if len(self.dataList) == 5:
                self.produce_json_file()        
        self.produce_json_file()
    def analysis_tuple(self,StrBuf,tlvData):
        Ipver, Dir, L4_porto, Null, Src_port, Dst_Port = struct.unpack("4B2H", StrBuf[0:8])
        tlvData.proto = L4_porto
        tlvData.sport = Src_port
        tlvData.dport = Dst_Port
        if Ipver == 0:
            (Src_ip, Null, Null, Null, Dst_ip, Null, Null, Null) = struct.unpack("!8I", StrBuf[8:40])
            tlvData.sip = socket.inet_ntoa(struct.pack('I', socket.htonl(Src_ip)))
            tlvData.dip = socket.inet_ntoa(struct.pack('I', socket.htonl(Dst_ip)))
        else:
            Src_ipv6, Src_ipv6_1, Src_ipv6_2, Src_ipv6_3, Dst_ipv6, Dst_ipv6_1, Dst_ipv6_2, Dst_ipv6_3, = \
                            struct.unpack("8I", StrBuf[8:40])
            pass
    def analysis_host(self,StrBuf,len,tlvData):
        tlvData.host = StrBuf[0:len].decode() 
    def analysis_url(self,StrBuf,len,tlvData):
        tlvData.url = StrBuf[0:len].decode() 

    
