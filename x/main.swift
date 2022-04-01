//
//  main.swift
//  x
//
//  Created by wei li on 2022/3/28.
//

import Foundation
import CommonCrypto
import QuartzCore

print("Hi",CommandLine.arguments)

Salsa20.test();
 
func tt(){
    
    let BlockSizeAES128 = 16
    var key = [UInt8](repeating: 0, count: 32);
    var iv =  [UInt8](repeating: 0, count: BlockSizeAES128);
    
    var data = Data(repeating: 1, count: 64);
    let dataOutAvailable = data.count + BlockSizeAES128
    
    let dataOut = malloc(dataOutAvailable);
    var outSize = 0;
    
    let testCount = 10000;
    
    data.withUnsafeBytes { bf  in
        
        var startTime = CACurrentMediaTime();
        
        for _ in 0...testCount{
            CCCrypt(CCOperation(kCCEncrypt),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCOptions(kCCOptionPKCS7Padding),      /* kCCOptionPKCS7Padding, etc. */
                    &key,
                    kCCKeySizeAES256,
                    &iv,
                    bf.baseAddress,
                    bf.count,
                    dataOut,
                    dataOutAvailable,
                    &outSize);
        }
        
        let endTime = CACurrentMediaTime();
        print("timeAes",(endTime - startTime) * 1000)
        
         
    }
    
    var dataKey = Data(bytes: key, count: key.count)

    var nonce = [UInt8](repeating: 24, count: 8);
    
    var dout : Data = Data(repeating: 0, count: data.count);
    
    let st = CACurrentMediaTime();
    
    
    var BfAll: [UInt8]? = [UInt8](repeating: 0, count: 272);
    
    for _ in 0...testCount{
        try? Salsa20.sa_crypt(msg: &data, keyData: &dataKey, outData: &dout, nonce: &nonce ,preAllocBuffer: &BfAll)
    }
    
    let et = CACurrentMediaTime();
    print("salsa20:",(et - st) * 1000)
}

//tt();

 

