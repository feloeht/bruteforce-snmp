#!/usr/bin/python
import hashlib
import sys
import time

msg = "?"
target = "?"
msg_2 = msg.replace(target, "000000000000000000000000")
engineid = "?".decode('hex')

def caculate_md5(password):
	passwordlen =  len(password)
	if passwordlen == 0:
		return ""
	password_buf = ""
	count = 0
	password_index = 0
	while count < 1048576:
		for i in range(64):
			password_buf += password[password_index % passwordlen]
			password_index += 1
		count += 64

	h = hashlib.new('md5')
	h.update(password_buf)
	key = h.hexdigest().decode('hex')
	strpass = key + engineid + key

	h = hashlib.new('md5')
	h.update(strpass)
	key = h.hexdigest()
	entend_key = key + '00' * 48
	IPAD = '36' * 64
	k1 = "%0128x" % (int(entend_key, 16) ^ int(IPAD, 16))
	OPAD = '5c' * 64
	k2 = "%0128x" % (int(entend_key, 16) ^ int(OPAD, 16))
	input = k1 + msg_2

	h = hashlib.new('md5')
	h.update(input.decode('hex'))
	input = h.hexdigest()
	input = k2 + input

	h = hashlib.new('md5')
	h.update(input.decode('hex'))
	input = h.hexdigest()
	return input[:12*2]

with open('dico-snmp.txt') as fp:
	count_lignes = 0
	lignes = fp.readlines()
	lignestotal = len(lignes)
	print "Passwords to test : " + str(lignestotal)
	for line in lignes:
		if count_lignes % 100 == 0:
			print '%.2f %%' % float((count_lignes * 100.0) / lignestotal) + " (" + str(count_lignes) + " passwords tested)"
		password = line[:-1]
		ret = caculate_md5(password)
		count_lignes += 1
		if target == ret:
			print "password : " + password
			break
