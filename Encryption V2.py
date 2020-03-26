import pyaes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import DES3
import binascii
import time
from twofish import Twofish
import math
import random
import string

def generateKey():
    keyPair = RSA.generate(3072)
    pubKey = keyPair.publickey()
    pubKeyPEM = pubKey.exportKey()
    asciikeypub = pubKeyPEM.decode('ascii').split("\n")
    asciikeypub = "".join(asciikeypub[1:-1])
    return pubKey, asciikeypub


def AESEncrypt(key, plaintext):
    #start encrypt
    start = time.perf_counter()
    key = key.encode('utf-8')
    aes = pyaes.AESModeOfOperationCTR(key[:32])    
    ciphertext = aes.encrypt(plaintext)
    stop = time.perf_counter()
    #encrypt stop
    
    #stats begining
    lenght = len(ciphertext)
    timeDiff = stop - start
    return lenght, timeDiff

def RSAEncrypt(pubKey,msgB):
    #start encrypt
    start = time.perf_counter()    
    encryptor = PKCS1_OAEP.new(pubKey)
    encrypted = encryptor.encrypt(msgB)
    stop = time.perf_counter()    
    #encrypt stop
    
    #stats begining
    lenght = len(binascii.hexlify(encrypted))
    timeDiff = stop - start
    return lenght, timeDiff
    
def TripleDESEncrypt(key,msgB):
    #start encrypt
    start = time.perf_counter()     
    cipher = DES3.new(key[:24], DES3.MODE_CFB)
    encrypted = cipher.iv + cipher.encrypt(msgB)
    stop = time.perf_counter()    
    #encrypt stop    
    
    #stats begining
    lenght = len(binascii.hexlify(encrypted))
    timeDiff = stop - start
    return lenght, timeDiff
    


def TwofishEncryption(key,msgB):
    encrypted =""
    i = 0
    
    #start encrypt
    start = time.perf_counter()     
    loops = math.ceil(len(msgB) / 16)
    T = Twofish(key[:32].encode("UTF-8"))
    while i < loops:   
        x = T.encrypt(msgB[i:i+16])
        x = binascii.hexlify(x)
        x = x.decode("UTF-8")
        encrypted += x
        i += 1
    stop = time.perf_counter()    
    #encrypt stop    
    
    #stats begining
    lenght = len(encrypted)
    timeDiff = stop - start
    return lenght, timeDiff


def statsAnalysis(lenghtTF, timeDiffTF, lenghtTDES, timeDiffTDES, lenghtAES, timeDiffAES, lenghtRSA, timeDiffRAS):
    print("---Results---")
    lenghtTFAverage = Average(lenghtTF)
    timeDiffTFAverage = Average(timeDiffTF)
    
    lenghtTDESAverage = Average(lenghtTDES)
    timeDiffTDESAverage = Average(timeDiffTDES)
    
    lenghtAESAverage = Average(lenghtAES)
    timeDiffAESAverage = Average(timeDiffAES)
    
    lenghtRSAAverage = Average(lenghtRSA)
    timeDiffRASAverage = Average(timeDiffRAS)
    
    print("Twofish Time: " + str(timeDiffTFAverage * pow(10, 3)) + "ms")    
    print("Twofish Lenght: " + str(lenghtTFAverage))   
    
    print("TrippleDES Time: " + str(timeDiffTDESAverage * pow(10, 3)) + "ms")
    print("TrippleDES Lenght: " + str(lenghtTDESAverage))
    
    #print("RSA Time: " +str(timeDiffRASAverage* pow(10, 3)) + "ms")  
    #print("RSA Lenght: " + str(lenghtRSAAverage))    
    
    print("AES Time: " + str(timeDiffAESAverage* pow(10, 3)) + "ms")
    print("AES Lenght: " + str(lenghtAESAverage))   
    
    
def Average(lst): 
    return sum(lst) / len(lst) 
    
        
    
def main():
    lenghtTF, timeDiffTF, lenghtTDES, timeDiffTDES, lenghtAES, timeDiffAES, lenghtRSA, timeDiffRAS = ([] for i in range(8))
    
    for i in range(50):
        msg = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(1000))
        msgB = msg.encode('utf-8')
        print(i)
        pubKey, asciikeypub = generateKey()
        
        lenght, timeDiff = TwofishEncryption(asciikeypub, msgB)
        lenghtTF.append(lenght)
        timeDiffTF.append(timeDiff)
        
        lenght, timeDiff = TripleDESEncrypt(asciikeypub, msgB)
        lenghtTDES.append(lenght)
        timeDiffTDES.append(timeDiff)
        
        lenght, timeDiff= AESEncrypt(asciikeypub, msg)
        lenghtAES.append(lenght)
        timeDiffAES.append(timeDiff)
        
        #lenght, timeDiff = RSAEncrypt(pubKey, msgB)
        lenghtRSA.append(lenght)
        timeDiffRAS.append(timeDiff)
    print("done")
    statsAnalysis(lenghtTF, timeDiffTF, lenghtTDES, timeDiffTDES, lenghtAES, timeDiffAES, lenghtRSA, timeDiffRAS)
        

main()