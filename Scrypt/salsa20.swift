//
//  salsa20.swift
//  Scrypt
//
//  Created by wei li on 2022/3/28.
//

import Foundation

public enum SaError:Error{
    case NonceLengthError
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

@inline(__always)  func UInt64ToUint8Array(idx:UInt64,bf:inout [UInt8]){
    var idx0 = idx.littleEndian;
    _ = bf.withUnsafeMutableBytes { bf0  in
        withUnsafeBytes(of: &idx0) { bf  in
            memcpy(bf0.baseAddress , bf.baseAddress, 8);
        }
    }
}


public class Salsa20 {
    
    @inline(__always) static func initStream(strm:inout [UInt8],key:inout [UInt8],nonce:inout [UInt8],indexLittleEndian:inout [UInt8]){
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
    
    static private  func salsa20_block(out:inout [UInt8],stream:inout [UInt8],tmpStrm:inout [UInt8],ROUNDS:Int = 20){
        _ = tmpStrm.withUnsafeMutableBytes { bf in
            stream.withUnsafeBytes { bf2 in
                memcpy(bf.baseAddress, bf2.baseAddress, bf.count);
            }
        }
        
        tmpStrm.withUnsafeMutableBytes { bf  in
            let x = bf.baseAddress!.bindMemory(to: UInt32.self, capacity: 16)
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
            
            stream.withUnsafeBytes{ bfOri  in
                let oriStrm = bfOri.baseAddress!.bindMemory(to: UInt32.self, capacity: 16);
                out.withUnsafeMutableBytes{ bf2 in
                    let outStrm = bf2.baseAddress!.bindMemory(to: UInt32.self, capacity: 16);
                    for i in 0..<16{
                        outStrm[i] = x[i] &+ oriStrm[i];
                    }
                }
            }
        };
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
    
    @inline(__always)  static private func copyXsalsakey(strm:inout [UInt8], key:inout [UInt8]){
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
    
    
    static func sa_crypt(msg:inout Data,keyData:inout Data,outData:inout Data?,nonce:inout [UInt8]) throws {
        
        guard (nonce.count == 24 || nonce.count == 8) else{
            throw SaError.NonceLengthError
        }
        
        let isXsalsa20 = nonce.count == 24 ;
        
        var strm = [UInt8](repeating: 0, count: 64);
        var strmOut = [UInt8](repeating: 0, count: 64);
        var strmTmp = [UInt8](repeating: 0, count: 64);
        var key = [UInt8](repeating: 0, count: 32);
        
        
        
        keyData.withUnsafeBytes { bf  in
            let p = bf.baseAddress?.bindMemory(to: UInt8.self, capacity: key.count);
            memcpy(&key , p , key.count);
        }
        var key32Tmp = key.map {$0};
        /// clean
        defer{
            randomize(&key);
            randomize(&strm);
            randomize(&strmOut);
            randomize(&strmTmp);
            randomize(&key32Tmp);
        }
        
        outData = Data(capacity: msg.count);
        
        var idxBf8 = [UInt8](repeating: 0, count: 8);
        var nonce8 = [UInt8](repeating: 0, count: 8);
        
        msg.withUnsafeBytes { bf in
            let r = bf.count / 64;
            for i in 0..<r{
                _ = key32Tmp.withUnsafeMutableBytes { bfTmp  in
                    key.withUnsafeBytes { bfKey in
                        memcpy(bfTmp.baseAddress, bfKey.baseAddress, 32)
                    }
                }
                
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
                        outData!.append(z ^ strmOut[j]);
                    }
                }
            }
            
            let remain = bf.count % 64;
            if remain > 0{
                _ = key32Tmp.withUnsafeMutableBytes { bfTmp  in
                    key.withUnsafeBytes { bfKey in
                        memcpy(bfTmp.baseAddress, bfKey.baseAddress, 32)
                    }
                }
                
                if isXsalsa20{
                    for n in 0..<8{
                        idxBf8[n] = nonce[n+8];
                        nonce8[n] = nonce[n];
                    }
                    initStream(strm: &strm, key: &key32Tmp, nonce: &nonce8, indexLittleEndian: &idxBf8);
                    
                    salsa20_block(out: &strmOut, stream: &strm,tmpStrm: &strmTmp);
                    
                    _ = nonce.withUnsafeBytes { bf  in
                        nonce8.withUnsafeMutableBytes { bf8 in
                            memcpy(bf8.baseAddress, bf.baseAddress?.advanced(by: 16) , 8)
                        }
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
                    
                    initStream(strm: &strm, key: &key, nonce: &nonce, indexLittleEndian: &idxBf8);
                    
                    salsa20_block(out: &strmOut, stream: &strm,tmpStrm: &strmTmp);
                }
                
                
                
                
                msg.withUnsafeBytes { bfMsg  in
                    for j in 0..<remain{
                        let indexOfMsg = r * 64 + j;
                        let z = bfMsg[indexOfMsg]
                        outData!.append(z ^ strmOut[j]);
                    }
                }
            }
        }
    }
    
    
    static func test(){
        var key = "12345678901234567890123456789012".map {$0.asciiValue!};
        let nonce32 = "123456781234567812345678".map {$0.asciiValue!};
        let nonce8 = "12345670".map {$0.asciiValue!};
        var nonce = nonce32;
        
        let txt = "Say las va te lo worldhello worldhello worldhello worldhello worldhello worldhello worldhello world"
        var data = txt.data(using: .utf8)!;
        var dataKey = Data(bytes: &key, count: key.count);
        var outData : Data?;
        try! sa_crypt(msg: &data, keyData: &dataKey, outData: &outData, nonce: &nonce);
        
        var outData2 : Data?;
        try! sa_crypt(msg: &outData!, keyData: &dataKey, outData: &outData2, nonce: &nonce);
        let s = String(data: outData2!, encoding: .utf8)!;
        print("result",s == txt)
        print("result",outData!.base64EncodedString())
        
         
        var bf1 = [UInt8](repeating: 0, count: 9);
        UInt64ToUint8Array(idx: 0xff00ff0001, bf: &bf1);
        print(bf1)
        
    }
    
    
}
