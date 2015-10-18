__author__ = 'bug85'
#!python
# coding=utf-8

import os, sys, subprocess, hashlib, re, tempfile, binascii, base64
import rsa, requests
import tea

def fromhex(s):
	# Python 3: bytes.fromhex
	return bytes(bytearray.fromhex(s))

pubKey=rsa.PublicKey(int(
	'F20CE00BAE5361F8FA3AE9CEFA495362'
	'FF7DA1BA628F64A347F0A8C012BF0B25'
	'4A30CD92ABFFE7A6EE0DC424CB6166F8'
	'819EFA5BCCB20EDFB4AD02E412CCF579'
	'B1CA711D55B8B0B3AEB60153D5E0693A'
	'2A86F3167D7847A0CB8B00004716A909'
	'5D9BADC977CBB804DBDCBA6029A97108'
	'69A453F27DFDDF83C016D928B3CBF4C7',
	16
), 3)

def pwdencode(vcode, uin, pwd):
		# uin is the bytes of QQ number stored in unsigned long (8 bytes)
		salt = uin.replace(r'\x', '')
		h1 = hashlib.md5(pwd.encode()).digest()
		s2 = hashlib.md5(h1 + fromhex(salt)).hexdigest().upper()
		rsaH1 = binascii.b2a_hex(rsa.encrypt(h1, pubKey)).decode()
		rsaH1Len = hex(len(rsaH1) // 2)[2:]
		hexVcode = binascii.b2a_hex(vcode.upper().encode()).decode()
		vcodeLen = hex(len(hexVcode) // 2)[2:]
		l = len(vcodeLen)
		if l < 4:
			vcodeLen = '0' * (4 - l) + vcodeLen
		l = len(rsaH1Len)
		if l < 4:
			rsaH1Len = '0' * (4 - l) + rsaH1Len
		pwd1 = rsaH1Len + rsaH1 + salt + vcodeLen + hexVcode
		saltPwd = base64.b64encode(
			tea.encrypt(fromhex(pwd1), fromhex(s2))
		).decode().replace('/', '-').replace('+', '*').replace('=', '_')
		return saltPwd

print pwdencode('!EMD','\\x00\\x00\\x00\\x00\\x04\\x87\\x4d\\xe4','Stringint123')

 # function getEncryption(password, salt, vcode, isMd5) {
 #        vcode = vcode || "";
 #        password = password || "";
 #        var md5Pwd = isMd5 ? password : md5(password)
 #          , h1 = hexchar2bin(md5Pwd)
 #          , s2 = md5(h1 + salt)
 #          , rsaH1 = $pt.RSA.rsa_encrypt(h1)
 #          , rsaH1Len = (rsaH1.length / 2).toString(16)
 #          , hexVcode = TEA.strToBytes(vcode.toUpperCase(), true)
 #          , vcodeLen = Number(hexVcode.length / 2).toString(16);
 #        while (vcodeLen.length < 4) {
 #            vcodeLen = "0" + vcodeLen
 #        }
 #        while (rsaH1Len.length < 4) {
 #            rsaH1Len = "0" + rsaH1Len
 #        }
 #        TEA.initkey(s2);
 #        var saltPwd = TEA.enAsBase64(rsaH1Len + rsaH1 + TEA.strToBytes(salt) + vcodeLen + hexVcode);
 #        TEA.initkey("");
 #        setTimeout(function() {
 #            __monitor(488358, 1)
 #        }
 #        , 0);
 #        return saltPwd.replace(/[\/\+=]/g, function(a) {
 #            return {
 #                "/": "-",
 #                "+": "*",
 #                "=": "_"
 #            }[a]
 #        }
 #        )
 #    }