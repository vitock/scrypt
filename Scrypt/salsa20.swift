//
//  salsa20.swift
//  Scrypt
//
//  Created by wei li on 2022/3/28.
//

import Foundation

public enum SaError:Error{
    case NonceLengthError
    case preallocMemSizeNot272
}

@inline(__always) private func ROTL(a:UInt32,b:UInt32) -> UInt32{
    return (a << b) | (a >> (32-b))
}
@inline(__always) private func QR(_ a: inout UInt32,_ b:inout UInt32,_ c:inout UInt32,_ d:inout UInt32)  {
    b ^= ROTL(a: a &+ d , b: 7);
    c ^= ROTL(a: b &+ a , b: 9);
    d ^= ROTL(a: c &+ b , b: 13);
    a ^= ROTL(a: d &+ c , b: 18);
}




public class Salsa20 {
    
    typealias SaBuffer = UnsafeMutableBufferPointer<UInt8>
    
    @inline(__always) static func UInt64ToUint8Array(idx:UInt64,bf:inout SaBuffer){
        var idx0 = idx.littleEndian;
        _ = withUnsafeBytes(of: &idx0) { bf1  in
            memcpy(bf.baseAddress , bf1.baseAddress, 8);
        }
        
    }
    
    @inline(__always) static func initStream(strm:inout SaBuffer,key:inout SaBuffer,nonce:inout SaBuffer,indexLittleEndian:inout SaBuffer){
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
        
        //        var idx = index.littleEndian;
        //        withUnsafeBytes(of: &idx) { bf  in
        //            let p = bf.baseAddress!.bindMemory(to: UInt8.self, capacity: 64);
        //            for j  in 0..<8 {
        //                strm[32+j] = p[j]
        //            }
        //        }
        
    }
    
    @inline(__always) static   func salsa20_block(out:inout SaBuffer,stream:inout SaBuffer,tmpStrm:inout SaBuffer,ROUNDS:Int = 20){
        
        memcpy(tmpStrm.baseAddress, stream.baseAddress, tmpStrm.count);
        
        
        tmpStrm.baseAddress!.withMemoryRebound(to: UInt32.self, capacity: 16){ bf32 in
            let x = bf32;
            for _ in stride(from: 0, to: ROUNDS, by: 2) {
                
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
    
    
    
    static private func printStrm(_ strm:inout [UInt8]){
        print("---Stream Buff >>>>> ")
        strm.withUnsafeBytes { bf  in
            let pStrm = bf.baseAddress!.bindMemory(to: UInt32.self, capacity:bf.count/4);
            let Count = bf.count / 16
            for i in 0..<Count{
                
                let S = String(format: "%08x,%08x,%08x,%08x",pStrm[0 + i * 4],pStrm[1 + i * 4],pStrm[2 + i * 4],pStrm[3 + i * 4] )
                
                print(S);
            }
            
        }
    }
    
    static private func printU32Box(pStrm:UnsafePointer<UInt32>,line:Int = #line){
        print("--->> U32Box \(line)")
        for i in 0..<4{
            let S = String(format: "%08x,%08x,%08x,%08x",pStrm[0 + i * 4],pStrm[1 + i * 4],pStrm[2 + i * 4],pStrm[3 + i * 4] )
            
            print(S);
        }
    }
    
    static var rnd = SystemRandomNumberGenerator();
    public static func randomize(_ buffer:inout [UInt8]){
        
        let bytePerRandomElement = 8;
        let round = buffer.count / bytePerRandomElement ;
        let remain = buffer.count % bytePerRandomElement ;
        
        for i in 0..<round{
            var randNum = rnd.next();
            var randNum2 = rnd.next();
            
            withUnsafePointer(to: &randNum) { bf in
                bf.withMemoryRebound(to: UInt8.self, capacity: bytePerRandomElement) { p  in
                    
                    withUnsafePointer(to: &randNum2) { bf2 in
                        bf2.withMemoryRebound(to: UInt8.self, capacity: bytePerRandomElement) { p2  in
                            for j in 0..<bytePerRandomElement{
                                buffer[i * bytePerRandomElement + j] = p[j] ^ p2[bytePerRandomElement - j - 1]
                            }
                        }
                    }
                }
            };
        }
        
        var randNum = rnd.next();
        var randNum2 = rnd.next();
        withUnsafePointer(to: &randNum) { bf in
            bf.withMemoryRebound(to: UInt8.self, capacity: bytePerRandomElement) { p  in
                withUnsafePointer(to: &randNum2) { bf2 in
                    bf2.withMemoryRebound(to: UInt8.self, capacity: bytePerRandomElement) { p2  in
                        for j in 0..<remain{
                            buffer[round * bytePerRandomElement + j] = p[j] ^ p2[bytePerRandomElement - j - 1]
                        }
                    }
                }
                
            }
        };
        
    }
    
    @inline(__always)  static private func clean(_ buffer:inout SaBuffer){
        memset(buffer.baseAddress, 0, buffer.count);
    }
    
    @inline(__always)  static private func copyXsalsakey(strm:inout SaBuffer, key:inout SaBuffer){
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
    
    static func sa_crypt(msg:inout Data,keyData:inout Data,outData:inout Data,nonce:inout [UInt8] ,preAllocBuffer:inout [UInt8]?) throws {
        guard (nonce.count == 24 || nonce.count == 8) else{
            throw SaError.NonceLengthError
        }
        
        guard (outData.count == msg.count ) else{
            throw SaError.NonceLengthError
        }
        let BufferCount = 272;
        guard (preAllocBuffer == nil || preAllocBuffer!.count !=  BufferCount ) else{
            throw SaError.preallocMemSizeNot272
        }
        
        let isXsalsa20 = nonce.count == 24 ;
        
        var bufferOfAll :[UInt8];
        if preAllocBuffer != nil && preAllocBuffer!.count >= BufferCount{
            bufferOfAll = preAllocBuffer!
        }else{
            bufferOfAll = [UInt8](repeating: 0, count: BufferCount);
        }
        
        bufferOfAll.withUnsafeMutableBufferPointer{ bfAll in
            /// clean
            defer{
                clean(&bfAll)
            }
            
            
            var startPostion = 0;
            var strm = UnsafeMutableBufferPointer(start:bfAll.baseAddress, count: 64);
            
            startPostion += strm.count;
            var strmOut = UnsafeMutableBufferPointer(start:bfAll.baseAddress?.advanced(by: startPostion), count: 64);
            
            startPostion += strmOut.count;
            var strmTmp = UnsafeMutableBufferPointer(start:bfAll.baseAddress?.advanced(by: startPostion), count: 64);
            
            startPostion += strmTmp.count;
            var key = UnsafeMutableBufferPointer(start:bfAll.baseAddress?.advanced(by: startPostion), count: 32);
            
            startPostion += key.count;
            var key32Tmp = UnsafeMutableBufferPointer(start:bfAll.baseAddress?.advanced(by: startPostion), count: 32);
            
            startPostion += key32Tmp.count;
            var idxBf8 = UnsafeMutableBufferPointer(start:bfAll.baseAddress?.advanced(by: startPostion), count: 8);
            
            startPostion += idxBf8.count;
            var nonce8 = UnsafeMutableBufferPointer(start:bfAll.baseAddress?.advanced(by: startPostion), count: 8);
            startPostion += nonce8.count
            for i in 0..<8{
                nonce8[i] = nonce[i];
            }
             
            keyData.withUnsafeBytes { bf  in
                let p = bf.baseAddress?.bindMemory(to: UInt8.self, capacity: key.count);
                memcpy(key.baseAddress , p , key.count);
                memcpy(key32Tmp.baseAddress , p , key.count);
            }
            
            
             
            
            msg.withUnsafeBytes { bf in
                let r = bf.count / 64;
                for i in 0..<r{
                    memcpy(key32Tmp.baseAddress, key.baseAddress, 32)
                     
                    if isXsalsa20{
                        /// fill block-count with nonce
                        for n in 0..<8{
                            nonce8[n] = nonce[n];
                            idxBf8[n] = nonce[n+8];
                        }
                        initStream(strm: &strm, key: &key32Tmp, nonce: &nonce8, indexLittleEndian: &idxBf8);
                        salsa20_block(out: &strmOut, stream: &strm,tmpStrm: &strmTmp);
                        
                        for n in 0..<8{
                            nonce8[n] = nonce[n+16];
                        }
                        let idx = UInt64(i);
                        UInt64ToUint8Array(idx: idx, bf: &idxBf8)
                        copyXsalsakey(strm: &strmTmp, key: &key32Tmp);
                        initStream(strm: &strm, key: &key32Tmp, nonce: &nonce8, indexLittleEndian: &idxBf8);
                        salsa20_block(out: &strmOut, stream: &strm,tmpStrm: &strmTmp);
                        
                        
                        
                    }else{
                        for n in 0..<8{
                            nonce8[n] = nonce[n];
                        }
                        
                        let idx = UInt64(i);
                        UInt64ToUint8Array(idx: idx, bf: &idxBf8)
                        
                        initStream(strm: &strm, key: &key32Tmp, nonce: &nonce8, indexLittleEndian: &idxBf8);
                        salsa20_block(out: &strmOut, stream: &strm,tmpStrm: &strmTmp);
                    }
                    
                    
                    
                    
                    msg.withUnsafeBytes { bfMsg  in
                        for j in 0..<strmOut.count{
                            let indexOfMsg = i * 64 + j;
                            let z = bfMsg[indexOfMsg]
                            outData[indexOfMsg] = z ^ strmOut[j]
                        }
                    }
                }
                
                let remain = bf.count % 64;
                if remain > 0{
                    memcpy(key32Tmp.baseAddress, key.baseAddress, 32)
                    
                    if isXsalsa20{
                        for n in 0..<8{
                            idxBf8[n] = nonce[n+8];
                            nonce8[n] = nonce[n];
                        }
                        initStream(strm: &strm, key: &key32Tmp, nonce: &nonce8, indexLittleEndian: &idxBf8);
                        
                        salsa20_block(out: &strmOut, stream: &strm,tmpStrm: &strmTmp);
                        
                        for n in 0..<8{
                            nonce8[n] = nonce[n+16];
                        }
                        
                        let idx = UInt64(r);
                        UInt64ToUint8Array(idx: idx, bf: &idxBf8)
                        copyXsalsakey(strm: &strmTmp, key: &key32Tmp);
                        
                        initStream(strm: &strm, key: &key32Tmp, nonce: &nonce8, indexLittleEndian: &idxBf8);
                        salsa20_block(out: &strmOut, stream: &strm,tmpStrm: &strmTmp);
                        
                    }
                    else{
                        for n in 0..<8{
                            nonce8[n] = nonce[n];
                        }
                        UInt64ToUint8Array(idx: UInt64(r), bf: &idxBf8)
                        
                        initStream(strm: &strm, key: &key, nonce: &nonce8, indexLittleEndian: &idxBf8);
                        
                        salsa20_block(out: &strmOut, stream: &strm,tmpStrm: &strmTmp);
                    }
                    
                     
                    msg.withUnsafeBytes { bfMsg  in
                        for j in 0..<remain{
                            let indexOfMsg = r * 64 + j;
                            let z = bfMsg[indexOfMsg]
                            outData[indexOfMsg] = z ^ strmOut[j]
                        }
                    }
                }
            }
        }
    }
    
    
    
    static func sa_hash(msg32:inout [UInt8],out32:inout[UInt8]){
        var bfall = [UInt8](repeating: 0, count: 208);
        bfall.withUnsafeMutableBufferPointer { bf  in
            msg32.withUnsafeMutableBufferPointer {bfKey in
                var strm = UnsafeMutableBufferPointer(start:bf.baseAddress?.advanced(by: 0), count: 64);
                
                var strmOut = UnsafeMutableBufferPointer(start:bf.baseAddress?.advanced(by: 64), count: 64);
                
                var strmTmp = UnsafeMutableBufferPointer(start:bf.baseAddress?.advanced(by: 128), count: 64);
                
                var nonce8_1 = UnsafeMutableBufferPointer(start:bf.baseAddress?.advanced(by: 192), count: 8);
                var nonce8_2 = UnsafeMutableBufferPointer(start:bf.baseAddress?.advanced(by: 200), count: 8);
                
                initStream(strm: &strm, key: &bfKey, nonce: &nonce8_1, indexLittleEndian: &nonce8_2)
                salsa20_block(out: &strmOut, stream: &strm, tmpStrm: &strmTmp)
                
                
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
                /// choose Uint32  0, 5, 10, 15, 6, 7, 8, 9  without last
            }
            
            
        }
    }
    
    
    static func test(){
        var key = "12345678901234567890123456789012".map {$0.asciiValue!};
        var nonce32 = "123456781234567812345678".map {$0.asciiValue!};
        var nonce8 = "12345678".map {$0.asciiValue!};
        var nonce = nonce8;
        
        let txt = "lo worldhello worldhello worldhello worldhello worldhello worldhello worldhello world我lo worldhello worldhello worldhello worldhello worldhello worldhello worldhello world"
        var data = txt.data(using: .utf8)!;
        var dataKey = Data(bytes: &key, count: key.count);
        var outData : Data = data;
        var d:[UInt8]? = nil
        try! sa_crypt(msg: &data, keyData: &dataKey, outData: &outData, nonce: &nonce, preAllocBuffer: &d);
        
        var outData2 : Data = outData;
        try! sa_crypt(msg: &outData, keyData: &dataKey, outData: &outData2, nonce: &nonce,preAllocBuffer: &d);
        let s = String(data: outData2, encoding: .utf8)!;
        print("result",s == txt)
        print("result",s )
        print("result",outData.base64EncodedString())
         
        var msg32 = [UInt8](repeating: 0, count: 32);
        var msg32out = [UInt8](repeating: 0, count: 32);
        sa_hash(msg32: &msg32 , out32: &msg32out);
        print(msg32out)
        
        
    }
    
    
}
