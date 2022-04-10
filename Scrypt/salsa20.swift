//
//  salsa20.swift
//  Scrypt
//
//  Created by wei li on 2022/3/28.
//

import Foundation
import QuartzCore

public enum SaError:Error{
    case NonceLengthError
    case keyLengthNot32
}

public class Salsa20{
    @inline(__always) private func ROTL(a:UInt32,b:UInt32) -> UInt32{
        return (a << b) | (a >> (32-b))
    }
    @inline(__always) private func QR(_ a: inout UInt32,_ b:inout UInt32,_ c:inout UInt32,_ d:inout UInt32 )  {
        
        b ^= ROTL(a: a &+ d , b: 7);
        c ^= ROTL(a: b &+ a , b: 9);
        d ^= ROTL(a: c &+ b , b: 13);
        a ^= ROTL(a: d &+ c , b: 18);
    }
    
    
    typealias SaBuffer = UnsafeMutableBufferPointer<UInt8>
    let BufferCount = 384;
    private var encBuffer:UnsafeMutablePointer<UInt8>
    
    
    var nextBlockCount:UInt64;
    
    
    private var keyArrary:[UInt8];
    private var nonceArray:[UInt8];
    
    
    private var strm:SaBuffer;
    private var strmOut:SaBuffer;
    private var strmTmp:SaBuffer;
    private var key:SaBuffer;
    private var key32Tmp:SaBuffer;
    private var idxBf8:SaBuffer;
    private var nonce8:SaBuffer;
    
    
    
    private var nonce8_hash1:SaBuffer;
    private var nonce8_hash2:SaBuffer;
    private var msg32_hash:SaBuffer;
    
    
    convenience init(){
        let key = [UInt8](repeating: 0, count: 32);
        let nonce = [UInt8](repeating: 0, count: 8);
        try! self.init(key:key,nonce:nonce);
    }
    
    /// 0 salsa20 1 xsalsa20
    let salsaType:Int;
    
    public init(key:[UInt8],nonce:[UInt8]) throws {
        guard nonce.count == 8 || nonce.count == 24  else{
            throw SaError.NonceLengthError;
        }
        guard key.count == 32  else{
            throw SaError.keyLengthNot32;
        }
        
        salsaType = nonce.count == 24 ? 1 : 0;
        nextBlockCount = 0;
        
        encBuffer = UnsafeMutableRawPointer.allocate(byteCount: BufferCount, alignment: 4).bindMemory(to: UInt8.self, capacity: BufferCount);
        
        keyArrary = key;
        nonceArray = nonce;
        
        
        
        var startPostion = 0;
        strm = UnsafeMutableBufferPointer(start:encBuffer, count: 64);
        
        startPostion += strm.count;
        strmOut = UnsafeMutableBufferPointer(start:encBuffer.advanced(by: startPostion), count: 64);
        
        startPostion += strmOut.count;
        strmTmp = UnsafeMutableBufferPointer(start:encBuffer.advanced(by: startPostion), count: 64);
        
        startPostion += strmTmp.count;
        self.key = UnsafeMutableBufferPointer(start:encBuffer.advanced(by: startPostion), count: 32);
        
        startPostion += key.count;
        key32Tmp = UnsafeMutableBufferPointer(start:encBuffer.advanced(by: startPostion), count: 32);
        
        startPostion += key32Tmp.count;
        idxBf8 = UnsafeMutableBufferPointer(start:encBuffer.advanced(by: startPostion), count: 8);
        
        startPostion += idxBf8.count;
        nonce8 = UnsafeMutableBufferPointer(start:encBuffer.advanced(by: startPostion), count: 8);
        startPostion += nonce8.count
        
        nonce8_hash1 = UnsafeMutableBufferPointer(start:encBuffer.advanced(by: startPostion), count: 8);
        startPostion += nonce8_hash1.count
        
        nonce8_hash2 = UnsafeMutableBufferPointer(start:encBuffer.advanced(by: startPostion), count: 8);
        startPostion += nonce8_hash2.count
        
        msg32_hash  = UnsafeMutableBufferPointer(start:encBuffer.advanced(by: startPostion), count: 8);
        startPostion += msg32_hash.count
        
        leftBuff = UnsafeMutableBufferPointer(start:encBuffer.advanced(by: startPostion), count: 64);
        startPostion += leftBuff.count
        
        
        
        for i in 0..<8{
            nonce8[i] = nonceArray[i];
        }
        
        keyArrary.withUnsafeBytes { bf  in
            let p = bf.baseAddress?.bindMemory(to: UInt8.self, capacity: key.count);
            memcpy(self.key.baseAddress , p , key.count);
            memcpy(key32Tmp.baseAddress , p , key.count);
        }
        
        
        initStream(strm: &strm, key: &self.key , nonce: &nonce8, indexLittleEndian: &idxBf8);
    }
    
    @inline(__always) func initStream(strm:inout SaBuffer,key:inout SaBuffer,nonce:inout SaBuffer,indexLittleEndian:inout SaBuffer){
        // fill the constant "expand 32-byte k"
        // https://en.wikipedia.org/wiki/Salsa20
        strm[0] = 0x65;
        strm[1] = 0x78;
        strm[2] = 0x70;
        strm[3] = 0x61;
        
        strm[20] = 0x6e;
        strm[21] = 0x64;
        strm[22] = 0x20;
        strm[23] = 0x33;
        
        strm[40] = 0x32;
        strm[41] = 0x2d;
        strm[42] = 0x62;
        strm[43] = 0x79;
        
        strm[60] = 0x74;
        strm[61] = 0x65;
        strm[62] = 0x20;
        strm[63] = 0x6b;
        
        // nonce
        for i in 0..<nonce.count{
            strm[i + 24] = nonce[i]
        }
        
        // key
        for i in 0..<16{
            strm[4 + i] = key[i];
            strm[44 + i] = key[16 + i];
        }
        /// block-count
        
        for j in 0..<8{
            strm[32+j] = indexLittleEndian[j]
        }
        
    }
    
    @inline(__always) private func salsa20_block(out:inout SaBuffer,stream:inout SaBuffer,tmpStrm:inout SaBuffer,ROUNDS:Int = 20){
        memcpy(tmpStrm.baseAddress, stream.baseAddress, tmpStrm.count);
        
        
        tmpStrm.baseAddress!.withMemoryRebound(to: UInt32.self, capacity: 16){ bf32 in
            let x = bf32;
            for k in stride(from: 0, to: ROUNDS, by: 2) {
                 
                QR(&x[ 0], &x[ 4], &x[ 8], &x[12]);    // column 1
                
                QR(&x[ 5], &x[ 9], &x[13], &x[ 1]);    // column 2
                QR(&x[10], &x[14], &x[ 2], &x[ 6]);    // column 3
                QR(&x[15], &x[ 3], &x[ 7], &x[11]);    // column 4
                // Even round
                QR(&x[ 0], &x[ 1], &x[ 2], &x[ 3]);    // row 1
                QR(&x[ 5], &x[ 6], &x[ 7], &x[ 4]);    // row 2
                QR(&x[10], &x[11], &x[ 8], &x[ 9]);    // row 3
                QR(&x[15], &x[12], &x[13], &x[14]);    // row 4
            }
            
            stream.baseAddress!.withMemoryRebound(to: UInt32.self, capacity: 16){ oriStrm in
                out.baseAddress!.withMemoryRebound(to: UInt32.self, capacity: 16) { outStrm  in
                    for i in 0..<16{
                        outStrm[i] = x[i] &+ oriStrm[i];
                    }
                }
                
            }
        }
    }
    
    @inline(__always) private func copyXsalsakey(strm:inout SaBuffer, key:inout SaBuffer){
        // z0, z5, z10, z15, z6, z7, z8, z9 as new Key
        
        let idxOfUint32 = [0,5,10,15,6,7,8,9];
        var idx = 0
        for i in 0..<idxOfUint32.count{
            let idxOfStrm = idxOfUint32[i] * 4;
            key[idx] = strm[idxOfStrm];
            idx += 1;
            key[idx] = strm[idxOfStrm + 1];
            idx += 1;
            key[idx] = strm[idxOfStrm + 2];
            idx += 1;
            key[idx] = strm[idxOfStrm + 3];
            idx += 1;
        }
        
    }
    
    
    
    @inline(__always) func UInt64ToUint8Array(idx:UInt64,bf:inout SaBuffer){
        var idx0 = idx.littleEndian;
        _ = withUnsafeBytes(of: &idx0) { bf1  in
            memcpy(bf.baseAddress , bf1.baseAddress, 8);
        }
        
    }
    
    @inline(__always) func UInt64ToSteam(idx:UInt64,strm:inout SaBuffer){
        var idx0 = idx.littleEndian;
        withUnsafeBytes(of: &idx0) { bf1  in
            strm[32] = bf1[0]
            strm[33] = bf1[1]
            strm[34] = bf1[2]
            strm[35] = bf1[3]
            strm[36] = bf1[4]
            strm[37] = bf1[5]
            strm[38] = bf1[6]
            strm[39] = bf1[7]
        }
        
    }
    
    
    
    
    var leftSize:Int = 0;
    var leftBuff:SaBuffer
    /**
     *  the best size of data is 64 * N;
     *  inData and outData must have same size;
     *
     *  only encrypt chunk size = N * 64 ;
     *  do the left on final() function
     *
     */
    public func update(inData: UnsafeRawPointer,outData: UnsafeMutableRawPointer,size:Int,outSize:inout Int){
        guard size > 0  else{
            outSize = 0;
            return;
        }
        
        var preLeftCount = leftSize
        leftSize +=  size;
        let inbf = inData.bindMemory(to: UInt8.self, capacity: size);
        let outbf = outData.bindMemory(to: UInt8.self, capacity: size);
        var cryptCount = 0;
        var incryptCursor = 0;
        while leftSize >= 64 {
            
            if salsaType == 0{
                UInt64ToSteam(idx:nextBlockCount,strm: &strm)
                salsa20_block(out: &strmOut, stream: &strm,tmpStrm: &strmTmp);
            }else{
                for n in 0..<8{
                    nonce8[n] = nonceArray[n];
                    idxBf8[n] = nonceArray[n+8];
                }
                initStream(strm: &strm, key: &key, nonce: &nonce8, indexLittleEndian: &idxBf8);
                salsa20_block(out: &strmOut, stream: &strm,tmpStrm: &strmTmp);
                    
                for n in 0..<8{
                    nonce8[n] = nonceArray[n+16];
                }
                
                UInt64ToUint8Array(idx: nextBlockCount, bf: &idxBf8)
                copyXsalsakey(strm: &strmTmp, key: &key32Tmp);
                initStream(strm: &strm, key: &key32Tmp, nonce: &nonce8, indexLittleEndian: &idxBf8);
                salsa20_block(out: &strmOut, stream: &strm,tmpStrm: &strmTmp);
            }
          
            // pre left data
            
            var i = 0;
            while i < 64{
                if(preLeftCount > 0){
                    for j in 0..<preLeftCount{
                        outbf[j] = leftBuff[j] ^ strmOut[ j]
                    }
                    i += preLeftCount;
                    preLeftCount = 0;
                }
                
                outbf[i + cryptCount] = inbf[incryptCursor] ^ strmOut[ i];
                incryptCursor += 1;
                
                i += 1;
            }
            
            
            
            cryptCount += 64;
            leftSize -= 64;
            nextBlockCount += 1;
        }
        
        outSize = cryptCount
        
        
        /// copy left to left buffer
   
        if(leftSize > 0){
            memcpy(leftBuff.baseAddress!.advanced(by: preLeftCount), inData.advanced(by: incryptCursor), leftSize - preLeftCount);
        }
        
    }
    
    
    public func reset(){
        leftSize = 0;
        nextBlockCount = 0;
    }
    
    public func final(outData: UnsafeMutableRawPointer,outSize:inout Int){
        if(leftSize == 0){
            outSize = 0;
            reset()
            clean()
            return;
        }
        
        if salsaType == 0{
            UInt64ToSteam(idx:nextBlockCount,strm: &strm)
            salsa20_block(out: &strmOut, stream: &strm,tmpStrm: &strmTmp);
        }else{
            for n in 0..<8{
                nonce8[n] = nonceArray[n];
                idxBf8[n] = nonceArray[n+8];
            }
            initStream(strm: &strm, key: &key, nonce: &nonce8, indexLittleEndian: &idxBf8);
            salsa20_block(out: &strmOut, stream: &strm,tmpStrm: &strmTmp);
                
            for n in 0..<8{
                nonce8[n] = nonceArray[n+16];
            }
            
            UInt64ToUint8Array(idx: nextBlockCount, bf: &idxBf8)
            copyXsalsakey(strm: &strmTmp, key: &key32Tmp);
            initStream(strm: &strm, key: &key32Tmp, nonce: &nonce8, indexLittleEndian: &idxBf8);
            salsa20_block(out: &strmOut, stream: &strm,tmpStrm: &strmTmp);
        }
        
        let inbf = leftBuff
        let oubf = outData.bindMemory(to: UInt8.self, capacity: leftSize);
        
        for i in 0..<leftSize {
            let msk = strmOut[ i];
            oubf[i] = inbf[i] ^ msk
        }
        
        outSize = leftSize;
        reset()
        clean()
    }
    
    public func clean(){
        memset(encBuffer, 0, BufferCount)
        for i in 0..<keyArrary.count{
            keyArrary[i] = 0;
        }
        for i in 0..<nonceArray.count{
            keyArrary[i] = 0;
        }
        
    }
    deinit {
        clean();
        encBuffer.deallocate()
    }
    
    func sa_64ByteTo64Byte(inBf:UnsafeRawPointer,outBf:UnsafeMutableRawPointer,ROUNDs:Int = 8){
        memcpy(strm.baseAddress, inBf, 64);
        salsa20_block(out: &strmOut, stream: &strm, tmpStrm: &strmTmp,ROUNDS: ROUNDs)
        memcpy(outBf, strmOut.baseAddress, 64)
    }
    
    func sa_hash(msg32:inout [UInt8],out32:inout[UInt8]){
        
        memset(nonce8_hash2.baseAddress, 0, 8);
        if(nonceArray.count > 8){
            for i in 0..<8{
                nonce8_hash2[i] = nonceArray[8 + i];
            }
        }
        for i in 0..<8{
            nonce8_hash1[i] = nonceArray[i];
        }
        
        msg32.withUnsafeMutableBufferPointer { bfMsg in
            initStream(strm: &strm, key: &bfMsg, nonce: &nonce8_hash1, indexLittleEndian: &nonce8_hash2)
            salsa20_block(out: &strmOut, stream: &strm, tmpStrm: &strmTmp)
        }
        
        //              choose Uint32  0, 5, 10, 15, 6, 7, 8, 9  without last
        strmTmp.withUnsafeBytes { bfTmp in
            let bfTmp32 = bfTmp.baseAddress!.bindMemory(to: UInt32.self, capacity: 16);
            out32.withUnsafeMutableBytes { bfOut in
                let bfOut32 = bfOut.baseAddress!.bindMemory(to: UInt32.self, capacity: 8)
                bfOut32[0] = bfTmp32[0];
                bfOut32[1] = bfTmp32[5];
                bfOut32[2] = bfTmp32[10];
                bfOut32[3] = bfTmp32[15];
                bfOut32[4] = bfTmp32[6];
                bfOut32[5] = bfTmp32[7];
                bfOut32[6] = bfTmp32[8];
                bfOut32[7] = bfTmp32[9];
            }
            
        }
        
    }
    
    static var rnd = SystemRandomNumberGenerator();
    public static func randomize(_ buffer:inout [UInt8]){
        let bytePerRandomElement = 8;
        let round = buffer.count / bytePerRandomElement ;
        let remain = buffer.count % bytePerRandomElement ;
        
        for i in 0..<round{
            var randNum = rnd.next();
            withUnsafePointer(to: &randNum) { bf in
                bf.withMemoryRebound(to: UInt8.self, capacity: bytePerRandomElement) { p  in
                    for j in 0..<bytePerRandomElement{
                        buffer[i * bytePerRandomElement + j] = p[j]
                    }
                }
            };
        }
        
        var randNum = rnd.next();
        withUnsafePointer(to: &randNum) { bf in
            bf.withMemoryRebound(to: UInt8.self, capacity: bytePerRandomElement) { p  in
                for j in 0..<remain{
                    buffer[round * bytePerRandomElement + j] = p[j]
                }
            }
        };
    }
    
    // MARK:
    public static func sa_crypt(msg:inout Data,keyData:inout Data,outData:inout Data,nonce:inout [UInt8] ) throws {
        guard (nonce.count == 24 || nonce.count == 8) else{
            throw SaError.NonceLengthError
        }
        
        guard (outData.count == msg.count ) else{
            throw SaError.NonceLengthError
        }
        var key = [UInt8](repeating: 0, count: 32);
        for i in 0..<keyData.count{
            key[i] = keyData[i];
        }
        
        msg.withUnsafeBytes { bfMsg in
            outData.withUnsafeMutableBytes { bfOut in
                let sa = try! Salsa20(key: key , nonce: nonce)
                
                var outSize = 0;
                sa.update(inData: bfMsg.baseAddress!, outData: bfOut.baseAddress!, size: bfOut.count,outSize: &outSize);
                
                if(outSize == bfOut.count){
                    sa.clean();
                }else{
                    sa.final(outData: bfOut.baseAddress!.advanced(by: outSize), outSize: &outSize);
                }
                
                
            }
        }
        
        
        
        
    }
    func printStm(_ s:inout SaBuffer,_ msg:String = "",fn:String = #function){
        Salsa20.printStm(&s,msg,fn:fn)
    }
    static func printStm(_ s:inout SaBuffer,_ msg:String = "",fn:String = #function){
        var i = 0 ;
        print("----\(fn)-----" + msg);
        
        var str = ""
        while i < s.count{
            let str1 = String(format: "%02x%02x%02x%02x", s[i],s[i + 1],s[i + 2],s[i + 3])
            str += str1 + " "
            i += 4;
            
            if(i % 16 == 0){
                str += "\n"
            }
        }
        print(str);
    }

}


