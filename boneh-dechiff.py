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
from boneh_chiff import IBE

#if we want to work of fields different than Z/pZ
FiniteField = finiteField.FiniteField
Polynomial = polynomial.Polynomial
ModifWeil = WeilPairing.ModifWeilPairing
EllipticCurve2 = ellipticCurve.EllipticCurve
Point2 = ellipticCurve.Point

#if we want to work only over the field Z/pZ
EllipticCurve=ellipticCurveMod.EllipticCurve
Point=ellipticCurveMod.Point
Infinity=ellipticCurveMod.Infinity
ModP = modular.ModP

#第二个哈希函数：在阶为l的Fp^2域上选择一个元素输入
#输出一个长度为n的字符串
#  Fp^2 -> {0,1}^n
#second hash function: input an element of order q in Fp^2 and outputs a string of length n
#where the length of the message is n
def hash3 (value, lengthMessage):
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
		
	output = bytearray(hash.encode())

	return output

# a,b做异或操作
#xor function: bitwise addition	
def xor (a,b):
	c = bytearray(len(a))
	for i in range(len(a)):
		c[i] = a[i] ^ b[i]
	return c

	
	
# #q：Fp^2域的阶
# q = 56453
#
# #p=2mod3, p=6q-1
#
# #p = 338717
# p = int(6 * q - 1)
#
# #一个域
# Fp2 = FiniteField(p, 2, Polynomial([ModP(1,p),ModP(1,p),ModP(1,p)],p)) #for q=56453
#
# #椭圆曲线: y*y + a1*x*y +a3*y = x*x*x + a2*x*x + a6
# #其中ai(i=1,2,3,5,6), 是域Fp2上的点
# #默认：a1=a3=0, 选取：a2=0, a6=1
# #得：y^2 = x^3 + 1
# E2 = EllipticCurve2( Fp2([0]), Fp2([1]), Fp2)
#
# #b是什么？？
# b = Fp2([0,1])
#
# DIDCordX = input("Enter the X-coordinate for the Point DID as an integer: ")
#
# DIDCordY = input("Enter the Y-coordinate for the Point DID as an integer: ")
#
#
# print("-------------------------------")
#
#
# print("Decryption")
#
# # 将点(DIDCordX, DIDCordY) 表示成Fp2的一个点
# DID = Point2(E2, Fp2([DIDCordX]), Fp2([DIDCordY]))
#
# #------------------------这是为什么！！-------------------------
#
# # cypherACordX = 240099
# # cypherACordY = 283222
# cypherACordX = 233844
# cypherACordY = 32655
#
# cypherA = Point2(E2, Fp2([cypherACordX]), Fp2([cypherACordY]))
#
# print("The first value of the cyphertext is:")
# print(cypherA)
# #//----------------------这是为什么！！---------------------------
#
# cyphertext = input("Enter the encrypted message, which you want to decrypt: ")
# cyphertext = binascii.unhexlify(cyphertext)
#
# length = len(cyphertext)
#
# hID = ModifWeil(DID, cypherA, q , b)
#
# print("hID is equal to:")
# print(hID)
#
# hash = hash3(hID, length)
#
# print("The decrypted message is:")
# c = xor(cyphertext , hash)
# print(c.decode())


if __name__=='__main__':
	ibe = IBE()
	# cyphertext = input("Enter the encrypted message, which you want to decrypt: ")
	cypher_texts = ibe.load_cypher_text()
	ID = input("Please enter your ID: ")

	count = 0
	for cypher_text in cypher_texts:
		if str(ID) == str(cypher_text['ID']):
			print("————————————")
			print("you have a message!")
			ibe.load_sys_paras()
			DIDCordX, DIDCordY = ibe.extract(ID)
			# DIDCordX = input("Enter the X-coordinate for the Point DID as an integer: ")
			# DIDCordY = input("Enter the Y-coordinate for the Point DID as an integer: ")
			ibe.decript(DIDCordX, DIDCordY, cypher_text)
			# ibe.decript(2, 3, cypher_text)
			count = count+1
	if count == 0:
		print("You have no message yet.")