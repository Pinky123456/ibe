#python modules
import hashlib
import binascii
import os
import random
import binascii
import json

#general modules written by myself
import modular
import ellipticCurveMod
import ellipticCurve
import finiteField
import polynomial
import WeilPairing
#if we want to work of fields different than Z/pZ
FiniteField = finiteField.FiniteField
Polynomial = polynomial.Polynomial
ModifWeil = WeilPairing.ModifWeilPairing
EllipticCurve2=ellipticCurve.EllipticCurve
Point2=ellipticCurve.Point

#if we want to work only over the field Z/pZ
EllipticCurve=ellipticCurveMod.EllipticCurve
Point=ellipticCurveMod.Point
Infinity=ellipticCurveMod.Infinity
ModP = modular.ModP

#一个类：用于存储密文，密文包括两个参数a,b
#class to store the cyphertext
class Ciphertext (object):
    def __init__(self, U, V):
        self.U = U
        self.V = V
        
    def __str__(self):
        return "The first value of the cypher text is: {}".format(self.U) + "The Second value of the cypher text is: {}".format(self.V)
        # return "%s and %s" % (self.U, self.V)

class IBE():

    def __init__(self, seed=None):
        self.outputFile = open('parameters.txt','w')
        self.P = None
        self.Ppub = None
        self.EC = None
        self.p = None
        self.q = None
        self.Fp = None
        self.Fp2 = None
        self.b = None
        self.s = None
        self.seed = seed
    #椭圆曲线：y^2 = x^3 + 1

    #在椭圆曲线上选取一个点，从y=3开始计算
    #find a point on the elliptic curve
    #starting with the y coordinate
    def findPoint(self, EC, q, p):
        i = int(3)
        while True:
            #replace y by value an find the x value
            # Py = i mod p
            Py = ModP(i,p)
            Px = (Py*Py-ModP(1,p))
            Px = ModP(Px.n**(1/3.0),p)
            #if a point and order correct, return it
            if EC.isPoint(Px,Py):
                P = Point(EC, Px, Py)
                #这个函数是什么意思呢？？
                if isinstance(P*q, Infinity):
                    return P
                #6*P is of order 1 or q, check proposition
                elif isinstance(6*P*q, Infinity):
                    return 6*P
            i = i + 1
            #if we tried too much possibilities, we stop the program
            if i > 300000:
                raise Exception("No point could be found")

    #在椭圆曲线上选取一个点，从x=3开始计算
    #find a point on the elliptic curve
    #starting with the x coordinate
    #test have shown that in most cases this one finds faster a point
    def findPoint2(self, EC,q, p):
        i = int(3)
        while True:
            #replace x by value and find y
            Px = ModP(i,p)
            Py = (Px*Px*Px+ModP(1,p))
            
            Py = ModP((Py.n)**(1/2.0),p)
            
            #if a point and order correct, return it
            if (EC.isPoint(Px,Py)):
                P = Point(EC, Px, Py)
                
                if isinstance(P*q, Infinity):
                    return P
                #6*P is of order 1 or q, check proposition
                elif isinstance(6*P*q, Infinity):
                    print(Px.n, Py.n)
                    return 6*P
            i = i + 1
            #if tried too much possibilites, try to find a point
            #by starting with y value
                
            if i > 300000:
                P = self.findPoint(EC,q,p)
               
                return P

    # 输入：不限长度的字符串ID（用户的身份标识）
    # 输出：域Fp上的一点
    # {0,1}* -> Fp
    # def hash (self, ID, EC, p, Q, q):
    def hash(self, ID):
        i = int(0)
        P = self.P
        q = self.q
        while True:
            #always initialize the hash function, so that both parties can find the same hashed point
            hash1 = hashlib.md5()
            hash1.update(ID.encode('utf-8'))
            #从哈希值中获取一个整数k，让它与基点Q相乘
            #get the integer from the hash value and multiply it to the base point
            k = int.from_bytes(hash1.digest(), byteorder='big')+i
            point = P*k
            #如果这个点的阶是q，返回它
            #if point of order q, return it
            if isinstance(point*q, Infinity) and point!=P:
                return point
                #6*point is of order 1 or q, check proposition
            elif isinstance(6*point*q, Infinity) and point!=P:
                return 6*point
            i = i + 1
            #if no point found, try to replace y by a value and find x
            if i > 300000:
                raise Exception("No point could be found")

    #第二个哈希函数：在阶为l的Fp^2域上选择一个元素输入
    #输出一个长度为n的字符串
    #  Fp^2 -> {0,1}^n
    #second hash function: input an element of order q in Fp^2 and outputs a string of length n
    #where the length of the message is n
    def hash3 (self, value, lengthMessage):
        sum = 0
        #sum the coefficients
        for i,a in enumerate(value.poly):
            sum = sum + a
        value = sum.n

        length = lengthMessage

        #Knuth's multiplicative method:
        hash = value * 2654435761 % (2**32)
        hash = bin(hash)
        hash = hash + hash[2:] + hash[2:] + hash[2:] + hash[2:] + hash[2:]
        hash = hash[:length]
            
        output = bytearray(hash.encode('utf-8'))

        return output

    # a,b做异或操作
    #xor function: bitwise addition 
    def xor (self, a, b):
        c = bytearray(len(a))
        for i in range(len(a)):
            c[i] = a[i] ^ b[i]
        return c
     
    def setup(self):
        #q=109
        #q=127 
        #q=199  
        #q=56453

        #defining the values for q and p of the scheme
        #q = int(127) #working!!!
        # 选取一个素数q
        q = int(56453)
        # q = int(127)
        p = int(int(6) * q - int(1))

        #define the two fields for later purpose
        #Fp = FiniteField(p,1) #for q=127
        #important to give the irreducible polynomial
        #Fp2 = FiniteField(p,2, Polynomial([ModP(6,p),ModP(758,p),ModP(1,p)],p)) #for q=127

        Fp = FiniteField(p, 1) #for q=56453
        print('Fp:%d' %Fp.fieldsize)
        Fp2 = FiniteField(p, 2, Polynomial([ModP(1, p), ModP(1, p), ModP(1, p)], p)) #for q=56453
        print(Polynomial([ModP(1, p), ModP(1, p), ModP(1, p)], p).coefficients)
        # Fp2 = FiniteField(p, 2, Polynomial([ModP(6, p), ModP(758, p), ModP(1, p)], p))  # for q=127

        #define ONE third root of unity of Fp^2
        #b = Fp2([249,341]) #for q = 127
        b = Fp2([0, 1]) #for q=56453

        print("The prime number q is:")
        print(q)
        self.outputFile.write('The prime number q is: '+str(q)+'\n')
        print("The prime number p is:")
        print(p)
        self.outputFile.write('The prime number p is: '+str(p)+'\n')
        print("The third root of unity is:")
        print(b)
        self.outputFile.write('Third root of unit is: '+str(b)+'\n')

        #condition of the scheme to work properly
        if (p-2) % 3 != 0:
            raise Exception("p does not verifiy the condition 2 mod 3")

        print("-------------------------------")
        print("The elliptic curve is:")
        EC = EllipticCurve(ModP(0,p),ModP(1,p))
        print(EC)


        print("The choosen point of order %d is:" % q)
        #this point is across to elliptic curve
        P = self.findPoint2(EC, q, p)
        print("this point P is across to elliptic curve: ", P)
        print("Check if the order of this point P is correct:")
        print(q*P)

        #这里应该是随机选取一个s, s属于Z*q
        #s in F_q^x
        #s in Z*_q
        # s = int(13)
        random.seed(self.seed)
        s = random.randint(2, q-1)
        Ppub = s*P

        self.P = P
        self.Ppub = Ppub
        self.EC = EC
        self.p = p
        self.q = q
        self.Fp = Fp
        self.Fp2 = Fp2
        self.b = b
        self.s = s

        self.store_sys_paras(p, q, P, Ppub, s)

        # return P, Ppub, EC, p, q, s, Fp2, b

    def store_sys_paras(self, p, q, P, Ppub, s):
        output = {}
        output['p'] = p
        output['q'] = q
        output['s'] = s

        point = [P.x.n, P.y.n]
        output['P'] = point

        point = [Ppub.x.n, Ppub.y.n]
        output['Ppub'] = point

        filename = 'sys_paras.json'
        # output['s'] = s
        with open(filename, 'w') as f_obj:
            json.dump(output, f_obj)
        # print("Ppub is equal to %s " % Ppub)

    def load_sys_paras(self):
        filename = 'sys_paras.json'
        # output['s'] = s
        with open(filename) as f_obj:
            sys_paras = json.load(f_obj)
        self.p = sys_paras['p']
        self.q = sys_paras['q']
        self.Fp = FiniteField(self.p,1)
        self.Fp2 = FiniteField(self.p, 2, Polynomial([ModP(1, self.p), ModP(1, self.p), ModP(1, self.p)], self.p))
        self.b = self.Fp2([0, 1])
        self.EC = EllipticCurve(ModP(0, self.p), ModP(1, self.p))
        self.s = sys_paras['s']
        P_x, P_y = self.get_point_from_list(sys_paras['P'])
        Ppub_x, Ppub_y = self.get_point_from_list(sys_paras['Ppub'])
        self.P = Point(self.EC, P_x, P_y)
        self.Ppub = Point(self.EC, Ppub_x, Ppub_y)

    def get_point_from_list(self, point):
        x = point[0]
        y = point[1]
        Px = ModP(x, self.p)
        Py = ModP(y, self.p)
        return Px, Py

    def extract(self, ID):
        s = self.s
        print("-------------------------------")
        print("The hashed point is:")

        QID = self.hash(ID)
        print(QID)

        DID = s*QID
        print("DID is equal to: %s" % DID)
        # self.outputFile.write('DID is equal to: '+str(DID)+'\n')
        return DID.x.n, DID.y.n

    # 向Alice发送密文
    def encrypt(self, ID, Msg):
        #M = "hello, this is a test. are you sure this is working? I could easily break your decryption!"

        q = self.q
        Ppub = self.Ppub
        Fp2 = self.Fp2
        b = self.b
        P = self.P

        print("-------------------------------")
        print("The receiver's QID is:")
        QID = self.hash(ID)
        # QID = hash(ID,EC,p, P, q)
        print(QID)

        # r应该随机取值
        #r in F_l^x
        random.seed(self.seed)
        r = random.randint(2, self.q-1)
        # r = int(343)
        # r = int(3247)
        #r = int(7)
        print("r is equal to:")
        print(r)


        print("-------------------------------")
        print("Test if points are of order")
        print(q)
        print("Point q*QID Alice")
        print(q*QID)
        print("Point q*Ppub")
        print(q*Ppub)

        print("-------------------------------")
        print("Weil pairing and verification")

        #define the points of the Elliptic Curve to the new
        #elliptic curve. we have an inclusion  
        #E(Fp) EC E(Fp^2)
        #but for further computation, we need to be able to
        #work over the new elliptic curve (for the weil pairing)
        E2 = EllipticCurve2( Fp2([0]), Fp2([1]), Fp2)
        QID2 = Point2(E2, Fp2([QID.x.n]), Fp2([QID.y.n]))
        Ppub2 = Point2(E2, Fp2([Ppub.x.n]), Fp2([Ppub.y.n]))

        gID = ModifWeil(QID2, Ppub2, q, b)

        print("gID is equal to:")
        print(gID)

        print("Check if it is a qth rooth:")
        print(gID**(q)) 


        print("-------------------------------")
        print("Encryption")
        print("The message to encrypt is : %s" % Msg)

        #decode the message to bytes and hash it
        Msg_bytes = bytearray(Msg.encode('utf-8'))
        H = self.hash3(gID**(r), len(Msg))

        #bitwise addition
        # 异或运算
        Msg_xor = self.xor(Msg_bytes, H)

        #create the cyphertext to send it to someone else
        cypher_text = Ciphertext(r*P, Msg_xor)

        self.outputFile.write('First value of the cyphertext: '+str(cypher_text.U)+'\n')
        self.outputFile.write('Second value of the cyphertext: '+str(cypher_text.V)+'\n')

        print("The message after encryption in bytes: ")
        print(Msg_xor)

        #create a hex representation of the encrypted message. this way, it is easier to communicate to a third party
        #and independent of the machine which is running.
        decoded = binascii.hexlify(Msg_xor)

        self.outputFile.write("This is a hex representation of the encrypted message."
            +"This hex-code needs to be entered to the decryption script: " 
            + str(decoded)[2:len(str(decoded))-1])

        self.store_cypher_text(ID, cypher_text)


    def store_cypher_text(self, ID, cypher_text):

        msgs = []
        msg = {}
        # a Point
        fist_value = []
        fist_value.append(cypher_text.U.x.n)
        fist_value.append(cypher_text.U.y.n)
        msg['ID'] = ID
        msg['U'] = fist_value

        decoded = binascii.hexlify(cypher_text.V) 
        msg['V'] = str(decoded)[2:len(str(decoded))-1]
        
        msgs.append(msg)

        filename = 'cypher_text.json'
        with open(filename, 'r') as f_obj:
            cypher_text_list = json.load(f_obj)
            for msg in msgs:
                cypher_text_list.append(msg)
        with open(filename, 'w') as f_obj:
            json.dump(cypher_text_list, f_obj)

    def load_cypher_text(self):
        filename = 'cypher_text.json'
        with open(filename) as f_obj:
            cypher_text = json.load(f_obj)
        return cypher_text

    def decript(self, DIDCordX, DIDCordY, cypher_text):

        self.load_sys_paras()
        p = self.p
        q = self.q
        Fp2 = self.Fp2
        b = self.b
        print("-------------------------------")
        print("Decryption")

        E2 = EllipticCurve2(Fp2([0]), Fp2([1]), Fp2)
        # 将点(DIDCordX, DIDCordY) 表示成Fp2的一个点
        DID = Point2(E2, Fp2([DIDCordX]), Fp2([DIDCordY]))

        #-------------------------------------------------
        # for r = 3247
        # cypherACordX = 233844
        # cypherACordY = 32655
        #
        # cypher_U = Point2(E2, Fp2([cypherACordX]), Fp2([cypherACordY]))
        # cypher_U = cypher_text.U

        print("The first value of the cyphertext is:")
        print(cypher_text['U'])
        piont_x = cypher_text['U'][0]
        piont_y = cypher_text['U'][1]
        cypher_U = Point2(E2, Fp2([piont_x]), Fp2([piont_y]))
        #//-------------------------------------------------

        cypher_V = binascii.unhexlify(cypher_text['V'])

        length = len(cypher_V)

        hID = ModifWeil(DID, cypher_U, q, b)

        print("hID is equal to:")
        print(hID)

        H = self.hash3(hID, length)

        print("The decrypted message is:")
        Msg = self.xor(cypher_V, H)
        print(Msg.decode())



if __name__=='__main__':

    #open file to save parameters gotten
    #through this computation
    ibe = IBE()

    print("==-------------------------------")

    # outputFile = open('parameters.txt','w')
    ibe.outputFile.write('If you are going to change the parameters in the encrypting file, you need to adapt some parameters in the decryption file'+'\n')
    ibe.outputFile.write('You will always need to adapt the coordinates of DID and you need to copy the last output line of this file to properly decrypt'+'\n')
    ibe.outputFile.write('-------------------------------'+'\n')


    print("-------------------------------")
        


    print("-------------------------------")
    print("Initializing:")
        
    ##-----------------------------setup(), 返回公开参数---------------------------------
    ibe.setup()
    # P, Ppub, EC, p, q, s, Fp2, b = setup()

    
    ##//-----------------------------setup(), 返回公开参数---------------------------------
    

    ##------------------------密钥生成-----------------------------

    ID = input("Enter the ID you want to use: ")
    #print("The ID is:")
    #ID = "steve@uni.lu"
    print(ID)

    ibe.extract(ID)

    ##//------------------------密钥生成-----------------------------

    ##-------------------------加密-----------------------------

    print("\n")
    M = input("Enter the message you want to encrypt: ")
    ibe.encrypt(ID, M)

    ##//-------------------------加密-----------------------------
    #close file

    ibe.outputFile.close()
    os.system('pause')