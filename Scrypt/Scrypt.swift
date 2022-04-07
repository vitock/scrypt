//
//  Scrypt.swift
//  Scrypt
//
//  Created by wei li on 2022/3/30.
//

import Foundation
import CommonCrypto
#if DEBUG
import QuartzCore
#endif
public class Scrypt{
    
    // sha256
    public let ParallelizationFactor:Int;
    public let BlockSizeFactor :Int;
//    var hLen = 32;
    public let lgIteration :Int; // 2^14
    
    var blockSize :Int { get {return BlockSizeFactor << 7}}
    var bfSize : Int { get {return blockSize * ParallelizationFactor }}

     
    let bfBlock : UnsafeMutableRawPointer;
    let bfRmixBlock : UnsafeMutableRawPointer;
    let bfRmixV : UnsafeMutableRawPointer;
    
    public init(ParallelizationFactor: Int,BlockSizeFactor:Int,lgIteration:Int){
        self.ParallelizationFactor = ParallelizationFactor;
        self.BlockSizeFactor = BlockSizeFactor;
        self.lgIteration = lgIteration;
        
        let blockSize = BlockSizeFactor << 7;
        let bfSize = blockSize * ParallelizationFactor;
         
        bfBlock = UnsafeMutableRawPointer.allocate(byteCount: bfSize , alignment: 4);
        bfBlock.initializeMemory(as: UInt8.self, repeating: 0, count: bfSize);
       
        bfRmixBlock = UnsafeMutableRawPointer.allocate(byteCount: bfSize , alignment: 4);
        bfRmixBlock.initializeMemory(as: UInt8.self, repeating: 0, count: bfSize);
        
        let idx = 1 << lgIteration;
        bfRmixV = UnsafeMutableRawPointer.allocate(byteCount: idx * blockSize * ParallelizationFactor , alignment: 4);
        bfRmixV.initializeMemory(as: UInt8.self, repeating: 0, count: idx * blockSize * ParallelizationFactor);
    }
    public convenience init(){
//        ParallelizationFactor = 1;
//        BlockSizeFactor = 8;
//        lgIteration = 14
        self.init(ParallelizationFactor:1,BlockSizeFactor:8,lgIteration:14);
    }
    
    func clean(){
        memset(bfBlock, 0, bfSize)
        memset(bfRmixBlock, 0, bfSize)
        let idx = 1 << lgIteration;
        memset(bfRmixV, 0, idx * blockSize * ParallelizationFactor)
    }
    deinit{
        
        clean()
        bfBlock.deallocate();
        bfRmixV.deallocate();
        bfRmixBlock.deallocate();
    }
    
    
    func printData(p:UnsafeRawPointer,size:Int,msg:String = ""){
        let d = Data(bytes: p , count: size);
        print(msg,size,d.tohexString());
    }
    
   
    
    
    @inline(__always)  func ROMix(block:UnsafeMutableRawPointer,outX:UnsafeMutableRawPointer,index:Int){
        
        let idx = 1 << lgIteration;
        let X = bfRmixBlock.advanced(by: index * blockSize);
        memcpy(X, block, blockSize);
         
        let bfV =  bfRmixV.advanced(by: blockSize * idx * index)
        let sa = Salsa20();
        
        let BfXCount = blockSize * 2;
        let bfX = UnsafeMutableRawPointer.allocate(byteCount: BfXCount, alignment: 4);
        
        for i in 0..<idx{
            let bfVi = bfV.advanced(by: i * blockSize);
            memcpy(bfVi, X , blockSize);
            BlockMix(block:X,out: X,sa:sa,tmpBf: bfX,index: index);
        }
        sa.final()
         
        let shift = (32 - lgIteration);
        for _ in 0..<idx{
            /// X last 64byte interger little endian , Uint32 is enough
            var j = X.load(fromByteOffset: blockSize - 64, as: UInt32.self);
            j = (j << shift)  >> shift;
            XOR(a: X , b: bfV.advanced(by: Int(j) * blockSize), out: X,size: blockSize);
            BlockMix(block: X , out: X, sa: sa, tmpBf: bfX, index: index)
          
        }
        
        memset(bfX, 0, BfXCount);
        memcpy(outX, X , blockSize);
        bfX.deallocate()
        
    }
    
    
    @inline(__always) func XOR( a:UnsafeMutableRawPointer, b:UnsafeMutableRawPointer,out:UnsafeMutableRawPointer, size:Int = 64){
        let pOut = out.bindMemory(to: UInt8.self, capacity: size);
        let pA = a.bindMemory(to: UInt8.self, capacity: size);
        let pB = b.bindMemory(to: UInt8.self, capacity: size);
        for i in 0..<size{
            pOut[i] = pA[i] ^ pB[i]
        }
    }
    func BlockMix(block:UnsafeMutableRawPointer,out:UnsafeMutableRawPointer,sa:Salsa20,tmpBf:UnsafeMutableRawPointer,index:Int ){
        let r = BlockSizeFactor;
        // last 64 byte chunk

        let last = block.advanced(by: blockSize - 64)
        let X = tmpBf;
        memcpy(X , last, 64);
        
        let tmpOut =  tmpBf.advanced(by: blockSize);
        for i in  0..<(2*r){
            let Bi = block.advanced(by: 64 * i)
            
            XOR(a: X , b: Bi , out: X);
            let outP:UnsafeMutableRawPointer
            if(i & 1 == 0){
                outP = tmpOut.advanced(by: i/2 * 64);
            }else{
                outP = tmpOut.advanced(by:  blockSize/2  +  i/2 * 64);
            }
            
            sa.sa_64ByteTo64Byte(inBf: X , outBf: outP)
            
            memcpy(X , outP, 64);
           
        }
        
        memcpy(out, tmpOut, blockSize);
    }
    
    
    public func generatePass(
        phrase:UnsafeRawPointer,
        phraseSize:Int,
        salt:UnsafeRawPointer,
        saltLen:Int,
        derivedKey:UnsafeMutableRawPointer,
        desiredKeyLen:Int
    ){
       
        let p = phrase.bindMemory(to: CChar.self, capacity: phraseSize)
        
        let  pout = bfBlock.bindMemory(to: UInt8.self, capacity: blockSize);
        let pSalt = salt.bindMemory(to: UInt8.self, capacity: saltLen);
        CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),p,phraseSize,pSalt,saltLen,CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), UInt32(1), pout , blockSize * ParallelizationFactor)

        
        for i in 0..<ParallelizationFactor{
            let pBlock = bfBlock.advanced(by: i * blockSize);
            ROMix(block: pBlock , outX: pBlock ,index:i)
        }
        
        
        let pBlick = bfBlock.bindMemory(to: UInt8.self, capacity: bfSize)
        let pderivedKey = derivedKey.bindMemory(to: UInt8.self, capacity: bfSize);
        
        CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),p,phraseSize,pBlick,bfSize,CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), UInt32(1), pderivedKey , desiredKeyLen)
        
        clean();
          
    }
}
 
extension Data {
    func tohexString() -> String{
        let hexAlphabet = Array("0123456789abcdef".unicodeScalars)
        let rd = reduce(into: "".unicodeScalars) { r, e  in
            r.append(hexAlphabet[Int(e / 0x10)])
            r.append(hexAlphabet[Int(e % 0x10)])
        };
        return String(rd);
    }
}
