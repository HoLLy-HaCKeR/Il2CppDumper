#encoding: utf-8
import idaapi
import random

def SetString(addr, comm):
	global index
	name = "StringLiteral_" + str(index);
	ret = idc.MakeNameEx(addr, name, SN_NOWARN)
	idc.MakeComm(addr, comm)
	index += 1

def SetName(addr, name):
	i = 0
	ret = idc.MakeNameEx(addr, name, SN_NOWARN)
	if ret == 0:
		new_name = name + '_' + str(addr)
		ret = idc.MakeNameEx(addr, str(new_name), SN_NOWARN)

def MakeFunction(start, end):
	if GetFunctionAttr(start, FUNCATTR_START) == 0xFFFFFFFF:
		idc.MakeFunction(start, end)
	else:
		idc.SetFunctionEnd(start, end)

index = 1
print('Making method name...')

