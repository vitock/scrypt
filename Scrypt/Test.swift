//
//  Test.swift
//  x
//
//  Created by wei li on 2022/4/10.
//

import Foundation
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

class Test{
    let msg = "1234567890123456723456789012345678901234567890123456789012345678901234567890123412345678901234567890123456789012345678901111"
    func main(){
        var t = t2();
        
        t3();
        
        for k in 1...1000{
            let z  = t1(1)
            if(z != t){
                for i in 0..<z.count{
                    if(z[i] != t[i]){
                        print("3333----->>>>",i,k);
                        break;
                    }
                }
                
                break;
            }
        }
       

       
         
    }
    func t1(_ step:Int) -> Data{
        
        var key = "12345678901234567890123456789012".map { $0.asciiValue!};
        var nonce = "123456781234567812345678".map { $0.asciiValue!};
        
        let sa = try! Salsa20(key: key , nonce: nonce);
        
        
        
        
        var out = [UInt8](repeating: 0, count: msg.count + 64);
        
        msg.withCString { bf  in
            var outSize = 0;
            
            var c = 0;
            var ec = 0
            let msgCount = msg.count;
            while c < msgCount{
                
                var sp = Int(arc4random_uniform(120));
                let step0 = min(msgCount - c , sp);
                sa.update(inData: bf.advanced(by: c), outData: &out[ec], size: step0, outSize: &outSize)
                c += sp;
                ec += outSize;
                
                print(sp);
            }
            
             
            sa.final(outData: &out[ec], outSize: &outSize);
            
            
        }
        let data = Data(bytes: out, count: msg.count);
        print(data.count,data.count & 63,data.base64EncodedString());
        return data;
        
        
    }
    
    func t2() -> Data{
        var key = "12345678901234567890123456789012".map { $0.asciiValue!};
        var nonce = "123456781234567812345678".map { $0.asciiValue!};
        var nonce8 = "12345678".map { $0.asciiValue!};
        
        var datain = msg.data(using: .utf8)
        var dataout = msg.data(using: .utf8)
        var dataout2 = msg.data(using: .utf8)
        
        var datakey = Data(bytes: &key, count: key.count);
        
        try! Salsa20.sa_crypt(msg: &datain!, keyData: &datakey, outData: &dataout!, nonce: &nonce)
        print(dataout!.count,dataout!.count & 63,dataout!.base64EncodedString())
        
        try! Salsa20.sa_crypt(msg: &datain!, keyData: &datakey, outData: &dataout2!, nonce: &nonce)
        print(dataout == dataout2)
        
        return dataout2!;
    }
    
    func t3(){
        let s = Scrypt.init();
        
        let key = "123123123123123123123123123123123123123123123123123123123123123123123123";
        let salt = "456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456456";
        var out = [UInt8](repeating: 0, count: 32);
        key.withCString { bfKey  in
            salt.withCString {bfS  in
                s.generatePass(phrase: bfKey, phraseSize: key.count, salt: bfS, saltLen: salt.count, derivedKey: &out , desiredKeyLen: out.count)
            }
        }
        
        let dkey = Data(bytes: out, count: out.count)
        print(dkey.tohexString())
        
    
        
    }
}
