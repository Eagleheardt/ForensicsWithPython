#!/usr/bin/python3

from tkinter import *
from tkinter import ttk
from tkinter.ttk import *
from tkinter import filedialog
import datetime
import subprocess
import re

root=Tk()#gui is called root
root.title("Forensics with Python")#set the title of the window
curCMD = StringVar() #will hold the command used to produce the output
#shell code to run commands
codeFrame = Frame(root)

Label(root,text="Code used to make this output:").grid(row=0,column=4,sticky=W)
Entry(root,textvariable=curCMD).grid(row=1,column=4,columnspan=2,sticky=W+E)

def returnCMD(cmd):
	curCMD.set(cmd)#updates the current command holder each time
	return(subprocess.check_output(cmd,shell=True,universal_newlines=False))
#get the partition table
#takes a volume
def getParTable(aVol):
	return(returnCMD("fdisk -l " + aVol))

#returns the SHA1 hash of anything input
def getSHA1(inFile="",bs="",skipAmt="",bNum=""):
	if bNum == "":#if no number of blocks specified, will take all of whatever specified
		return(returnCMD("dd if=" + inFile + " | openssl sha1"))
	else:
		return(returnCMD("dd if=" + inFile + " bs=" + bs + " skip=" + skipAmt + " count=" + bNum + " | openssl sha1"))
#returns the MD5 hash of anything input
def getMD5(inFile="",bs="",skipAmt="",bNum=""):
	if bNum == "":#if no number of blocks specified, willtake all of whatever specified
		return(returnCMD("dd if=" + inFile + " | openssl md5"))
	else:
		return(returnCMD("dd if=" + inFile + " bs=" + bs + " skip=" + skipAmt + " count=" + bNum + " | openssl md5"))
#get list of deleted items 
#Takes a specific partition
def getDELitems(aPart, offset):
	return(returnCMD("fls -rd -o " + offset + " " + aPart))
#Takes a specific partition
def getMFTitems(aPart, offset):
	return(returnCMD("fls -o " + offset + " " + aPart))
#get list of deleted items 
#Takes a specific partition and entry number
def getMetaData(aPart, offset, entNum):
	return(returnCMD("istat -o " + offset + " " + aPart + " " + entNum))
#Getnlist of file system information
#takes specific partition
def getFSInfo(aPart,offset):
	return(returnCMD("fsstat -o " + offset + " " + aPart))
#will extract a filelocation into an output file
def extractIntoFile (inFile="",outFile="",bs="",skipAmt="",bNum=""):
	if bNum == "":
		return(returnCMD("dd if=" + inFile + " of=" + outFile + " 2>&1"))
	elif outFile == "":
		return(returnCMD("dd if=" + inFile + " bs=" + bs + " skip=" + skipAmt + " count=" + bNum + " 2>&1"))
	else:
		return(returnCMD("dd if=" + inFile + " of=" + outFile + " bs=" + bs + " skip=" + skipAmt + " count=" + bNum + " 2>&1"))

def getHex(inFile="",bs="",skipAmt="",bNum=""):
	if bNum == "":#if no number of blocks specified, willtake all of whatever specified
		return(returnCMD("dd if=" + inFile + " | xxd"))
	else:
		return(returnCMD("dd if=" + inFile + " bs=" + bs + " skip=" + skipAmt + " count=" + bNum + " | xxd"))

def getFormatTime():
	return(str(datetime.datetime.now()).replace(" ", "-").translate({ord(c): None for c in "`!@#$%^&*()|\\\\ "}))

#will analyze the text box for information
def setParts(txtBox,aDictStart,aDictEnd,aPattern):
	aDictStart.clear()
	aDictEnd.clear()
	#extracts items into a list based on a pattern, from a textbox
	data = txtBox.get(1.0, END) # gets all the text in the box
	noStar = data.translate({ord(c): None for c in "*"}) #removes boot star
	noStarList = noStar.split()
	usePattern = re.compile(aPattern)
	matches = re.findall(usePattern, data)

	for x in matches:
		matchIndex = noStarList.index(x)
		listEntry = x.split("/")[-1]
		aDictStart[listEntry] = noStarList[matchIndex+1]
		aDictEnd[listEntry] = noStarList[matchIndex+2]
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
workingVolume = StringVar() #name/path of volume being used
workingVolume.set("")

partDictStart = {} #dictionary of partitions and their initial offsets
partDictEnd = {}#dictionary for ending offset of partition
entryDict = {}#dictionary that holds mft/del file entry and name
workingPart = StringVar() #name/path of selected partition
entryFormat = IntVar()#holds either the MFT or delfile pattern
entryFormat.set(1)
#1= del files :
#2= mft files -
entryNum = StringVar() #holds the mft/orphan file number
hashSet = set()#holds initial hash values for validation
userName = StringVar()
hasStarted = IntVar()
hasStarted.set(0)

outputFrame = Frame(root)#pack last or at grid off to the side, higest column
outSB = Scrollbar(outputFrame)
outSB.pack(side=RIGHT,fill=Y)
txtOutput = Text(outputFrame,yscrollcommand=outSB.set)#needs a name, will be called!
txtOutput.pack()
outSB.config(command=txtOutput.yview)

txtGrab = Text(root)
#never pack this
#this is only for grabbing outputs inbackground
idLabel = Label(root,text="Enter your name/ID:")
userEnter = Entry(root, textvariable=userName)
txtImgPath = Entry(root,textvariable=workingVolume,state=DISABLED)

#which hashtype 
#1 = MD5
#2 = SHA1
intHashType = IntVar()
intHashType.set(1)
workVolOnly = StringVar()
copyName = StringVar()#full name of the copy of the original
logName = StringVar()#keep track of where it's writing
logTime = StringVar()#start datetime of investigation

advancedFrame = Frame(root)
isAdvanced = IntVar()
isAdvanced.set(0)
intAdvanced = IntVar()

chkAdvanced = Checkbutton(advancedFrame,text="Explanation Mode",variable=intAdvanced)

#declare buttons here, add methods later with.config(command=COMMAND)
lstGUIparts = Listbox(root,selectmode=SINGLE) #listbox for the partitions :)
btnHashPart = Button(root,text="Hash Partition")
btnFSinfo = Button(root,text="File System Information")
btnDelFiles = Button(root,text="View Deleted Files")
btnMFT = Button(root,text="View MFT Files")

lstDelMft = Listbox(root,selectmode=SINGLE)
btnHashFile = Button(root,text="Hash File")
btnHexFile = Button(root,text="File Hex")
btnExtractFile = Button(root,text="Advanced\nFile\nOptions")
btnViewMetaData = Button(root,text="View Meta Data")
btnGetImg = Button(root,text="Select Image")
btnBegin = Button(root,text="Begin")

btnAdvanced = Button(advancedFrame,text="Enter Explanation Mode")
def btnAdvancedClick():
	try:
		logger=open(logName.get(),'a')
		logger.write(getFormatTime() + "\n")
		logger.write("User entered explanation mode. Investigation Abandoned.")
		logger.close()
		returnCMD("chattr +i " + logName.get())
		curCMD.set("")
	except Exception:
		pass

	if isAdvanced.get() is 1:
		txtOutput.delete(1.0,END)
		txtOutput.insert(END,"This button will allow you to enter explanation mode.")
		return

	isAdvanced.set(1)

	chkAdvanced.config(state=DISABLED)
	userEnter.config(state=DISABLED)
	btnQuit.pack(anchor=W)
	btnBegin.config(state=NORMAL)
	btnGetImg.config(state=NORMAL)
	
	btnBegin.grid(row=3,column=1,sticky=W)

	btnViewPartTable.grid(row=4,sticky=W)
	btnHashDrive.grid(row=4,column=1,sticky=W)
	btnReset.grid(row=4,column=2,sticky=W)

	lblIntroParts.grid(row=5,sticky=W)
	lstGUIparts.grid(row=6,rowspan=4,sticky=W+N+S)

	btnHashPart.grid(row=6,column=1,sticky=W)
	btnFSinfo.grid(row=7,column=1,sticky=W)
	btnDelFiles.grid(row=8,column=1,sticky=W)
	btnMFT.grid(row=9,column=1,sticky=W)

	lblDELMFTintro.grid(row=5,column=2,sticky=W)
	lstDelMft.grid(row=6,column=2,rowspan=4,sticky=W+N+S)
	#btnHexFile.grid(row=6,column=3,sticky=W)
	#btnHashFile.grid(row=7,column=3,sticky=W)
	btnViewMetaData.grid(row=8,column=3,sticky=W)
	btnExtractFile.grid(row=9,column=3,sticky=W)

btnAdvanced.config(command=btnAdvancedClick)

lblAdvanced = Label(advancedFrame,text="Warning: This will end your investigation!")
btnQuit = Button(advancedFrame,text="Quit Program",command=root.quit)

def advancedCheck():
	if intAdvanced.get() is 1:	
		if hasStarted.get() is 1:
			lblAdvanced.pack(anchor=W)
		btnAdvanced.pack(anchor=W)
	else:
		lblAdvanced.pack_forget()
		btnAdvanced.pack_forget()
		btnQuit.pack_forget()

chkAdvanced.config(command=advancedCheck)
chkAdvanced.pack(anchor=W)

def changeWorkingPart(evt):
	if isAdvanced.get() is 1:
		txtOutput.delete(1.0,END)
		txtOutput.insert(END,"This window holds the partitions of the working volume.")
		return
	w = evt.widget
	nDex = int(w.curselection()[0])
	workingPart.set(w.get(nDex))

lstGUIparts.bind('<<ListboxSelect>>',changeWorkingPart)

fileMessage = StringVar()#change when button click
fileMessage.set("Deleted files:")

lblDELMFTintro = Label(root,textvariable=fileMessage)

def changeDelMft(evt):
	if isAdvanced.get() is 1:
		txtOutput.delete(1.0,END)
		txtOutput.insert(END,"This window holds the deleted files or MFT entries for extra examination")
		return
	w = evt.widget
	nDex = int(w.curselection()[0])
	entryKey = w.get(nDex)
	#entryFormat - integer var
	#1= del files :
	#2= mft files -
	if entryFormat is 1:
		entryNum.set(entryKey.split()[0])
	else:
		entryNum.set(entryKey.split("-")[0])
	
lstDelMft.bind('<<ListboxSelect>>',changeDelMft)

#constants:
MFTent = "1024" #MFT entries are all 1024 bytes
sectSize = "512" #sectors are always 512 bytes

#begin controls for beginning an investigation

def btnGetImgClick():
	if isAdvanced.get() is 1:
		txtOutput.delete(1.0,END)
		txtOutput.insert(END,"This will bring up a window to select the file with which you'd like to work.\n")
		txtOutput.insert(END,"The file you select will be called the volume or working volume.")
		return

	if userName.get() == "":
		badName = Toplevel()
		badName.title("CrItIcAl ErRoR")
		badNameMsg = Message(badName,text="Must Enter User Name/ID.")
		badNameMsg.pack()
		badNameBtn = Button(badName, text="Close", command=badName.destroy)
		badNameBtn.pack()
		return

	tempFile = filedialog.askopenfilename()
	txtGrab.delete(1.0,END)
	txtGrab.insert(END,getParTable(tempFile))
	setParts(txtGrab,partDictStart,partDictEnd,tempFile + "[0-9]+")
	txtGrab.delete(1.0,END)
#checks if there's a valid partition table on image
	if len(partDictStart) is 0:
		#if no items in the list, then show error
		badImg = Toplevel()
		badImg.title("CrItIcAl ErRoR")
		badImgMsg = Message(badImg,text="Cannot read file image.")
		badImgMsg.pack()
		badImgBtn = Button(badImg, text="Close", command=badImg.destroy)
		badImgBtn.pack()
	else:
		workingVolume.set(tempFile)
		userEnter.config(state=DISABLED)
		btnBegin.grid(row=3,column=1,sticky=W)
		hasStarted.set(1)
		#disable the parts of the first Frame
btnGetImg.config(command=btnGetImgClick)


#/Investigations is the location for the logs

def btnBeginClick():
	if isAdvanced.get() is 1:
		txtOutput.delete(1.0,END)
		txtOutput.insert(END,"This button will confirm the beginning of the investigation.")
		return

	waitWindow = Toplevel()
	waitWindow.title("Advanced File Options")
	waitWindowMsg = Message(waitWindow,text="Ready to begin!")
	waitWindowMsg.pack()
	waitWindowBtn = Button(waitWindow, text="Ok", command=waitWindow.destroy)
	waitWindowBtn.pack()

	workVolList = workingVolume.get().split("/")
	workVolOnly.set(workVolList[-1])
	formatName = userName.get()
	formatName = formatName.translate({ord(c): None for c in "`!:@#$%^&*()| "})
	
	logTime.set(getFormatTime())	

	copyName.set("/Investigations/" + workVolOnly.get() + "-By-" + formatName + "-" + logTime.get() + ".dd")
	extractIntoFile(inFile=workingVolume.get(),outFile=copyName.get())
	
	logName.set(copyName.get() + "-log.txt")
	logger=open(logName.get(),'w')
	logger.write("Investigator: " + formatName + "\n")
	logger.write("Investigation of: " + workingVolume.get() + "\n")
	logger.write("Begun on: " + logTime.get() + "\n\n")
	txtGrab.delete(1.0,END)

	if intHashType.get() is 1:
		#copy, append date / investigator, python stringvarcheck, start log
		txtGrab.insert(END,getMD5(inFile=workingVolume.get()))
		logger.write("MD5 of original image:")
	else:
		txtGrab.insert(END,getSHA1(inFile=workingVolume.get()))
		logger.write("SHA1 of original image:")
		
	data = txtGrab.get(1.0,END)
	splitData = data.split("=")
	logger.write(splitData[-1].upper())

	hashSet.add(splitData[-1].upper())
	txtGrab.delete(1.0,END)
	
	if intHashType.get() is 1:
		#copy, append date / investigator, python stringvarcheck, start log
		txtGrab.insert(END,getMD5(inFile=copyName.get()))
		logger.write("MD5 of suspect image:")
	else:
		txtGrab.insert(END,getSHA1(inFile=copyName.get()))
		logger.write("SHA1 of suspect image:")

	data = txtGrab.get(1.0,END)
	splitData = data.split("=")
	logger.write(splitData[-1].upper())

	txtGrab.delete(1.0,END)
	hashSet.add(splitData[-1].upper())

	if len(hashSet) is not 1:
		badHash = Toplevel()
		badHash.title("CrItIcAl ErRoR")
		badHashMsg = Message(badHash,text="Hashes don't match")
		badHashMsg.pack()
		badHashBtn = Button(badHash, text="Exit", command=root.destroy)
		badHashBtn.pack()
	
	logger.write("\n")
	logger.close()
	
	btnViewPartTable.grid(row=4,sticky=W)
	btnHashDrive.grid(row=4,column=1,sticky=W)
	btnReset.grid(row=4,column=2,sticky=W)
	btnBegin.config(state=DISABLED)
	btnGetImg.config(state=DISABLED)
	curCMD.set("")

btnBegin.config(command=btnBeginClick)

hashFrame = Frame(root)

Label(hashFrame,text="Hash Mode:").grid(row=1,sticky=W)

Radiobutton(hashFrame,text="MD5",variable=intHashType,value=1).grid(row=2,sticky=W)
Radiobutton(hashFrame,text="SHA1",variable=intHashType,value=2).grid(row=3,sticky=W)

lblIntroParts = Label(root,text="Partitions:")

def btnViewPartTableClick():
	if isAdvanced.get() is 1:
		txtOutput.delete(1.0,END)
		txtOutput.insert(END,"This will allow you to view the partition table of the volume.\n")
		txtOutput.insert(END,"The partition table is a list of all partitions on the volume and the operating systems on each.")
		return
	logger=open(logName.get(),'a')
	logger.write(getFormatTime() + "\n")
	logger.write("User viewed partition table\n\n")
	logger.close()

	txtOutput.delete(1.0,END)
	txtOutput.insert(END,getParTable(workingVolume.get()))
	lstGUIparts.delete(0,END)
	for x,y in partDictStart.items():
		lstGUIparts.insert(END,x.split("/")[-1])
	lblIntroParts.grid(row=5,sticky=W)
	lstGUIparts.grid(row=6,rowspan=4,sticky=W+N+S)

	btnHashPart.grid(row=6,column=1,sticky=W)
	btnFSinfo.grid(row=7,column=1,sticky=W)
	btnDelFiles.grid(row=8,column=1,sticky=W)
	btnMFT.grid(row=9,column=1,sticky=W)

btnViewPartTable = Button(root,text="View Partition Table",command=btnViewPartTableClick)

def btnHashDriveClick():
	if isAdvanced.get() is 1:
		txtOutput.delete(1.0,END)
		txtOutput.insert(END,"This button will perform a hash on the entire drive.\nA hash will produce a digital fingerprint for a given piece of data.\nHash types supported by this program are MD5 and SHA1.")
		return
	logger=open(logName.get(),'a')
	logger.write(getFormatTime() + "\n")

	txtOutput.delete(1.0,END)

	if intHashType.get() is 1:
		txtOutput.insert(END,getMD5(workingVolume.get()))
		data = txtOutput.get(1.0,END)
		splitData = data.split("=")
		logger.write("User performed MD5 hash on whole drive\n")
		logger.write(splitData[-1].upper() + "\n")
		txtOutput.insert(END,"MD5 Hash Performed")
		
	else:
		txtOutput.insert(END,getSHA1(workingVolume.get()))
		data = txtOutput.get(1.0,END)
		splitData = data.split("=")
		logger.write("User performed SHA1 hash on whole drive\n")
		logger.write(splitData[-1].upper() + "\n")
		txtOutput.insert(END,"SHA1 Hash Performed")

	logger.close()

btnHashDrive = Button(root,text="Hash Drive",command=btnHashDriveClick)

def btnResetClick():
	if isAdvanced.get() is 1:
		txtOutput.delete(1.0,END)
		txtOutput.insert(END,"This would normally end your investigation")
		return
	logger=open(logName.get(),'a')
	logger.write(getFormatTime() + "\n")
	logger.write("User abandonded investigation")
	logger.close()
	returnCMD("chattr +i " + logName.get())
	root.destroy()

btnReset = Button(root,text="Quit",command=btnResetClick)

def btnHashPartClick():
	if isAdvanced.get() is 1:
		txtOutput.delete(1.0,END)
		txtOutput.insert(END,"This will produce a hash of the partition selected\nA hash will produce a digital fingerprint for a given piece of data.\nHash types supported by this program are MD5 and SHA1.")
		return

	vol = workingVolume.get()
	fsKey = workingPart.get()

	if fsKey == "":
		badPartSelect = Toplevel()
		badPartSelect.title("CrItIcAl ErRoR")
		badPartSelectMsg = Message(badPartSelect,text="Please select a partition.")
		badPartSelectMsg.pack()
		badPartSelectBtn = Button(badPartSelect, text="Close", command=badPartSelect.destroy)
		badPartSelectBtn.pack()
		return

	logger=open(logName.get(),'a')
	logger.write(getFormatTime() + "\n")
	logger.write("User hashed partition\n\n")

	byteDiff = int(partDictEnd[fsKey]) - int(partDictStart[fsKey])
	txtOutput.delete(1.0,END)

	if intHashType.get() is 1:
		txtOutput.insert(END,getMD5(inFile=vol,bs="1",skipAmt=str(partDictStart[str(fsKey)]),bNum=str(byteDiff)))
	else:
		txtOutput.insert(END,getSHA1(inFile=vol,bs="1",skipAmt=str(partDictStart[str(fsKey)]),bNum=str(byteDiff)))

	logger.close()

btnHashPart.config(command=btnHashPartClick)

def btnFSinfoClick():
	if isAdvanced.get() is 1:
		txtOutput.delete(1.0,END)
		txtOutput.insert(END,"This will give you the file system information on the selected partition\n")
		txtOutput.insert(END,"Available information includes cluster sizes, sector sizes, and operating system types")
		return
	
	vol = workingVolume.get()
	fsKey = workingPart.get()

	if fsKey == "":
		badPartSelect = Toplevel()
		badPartSelect.title("CrItIcAl ErRoR")
		badPartSelectMsg = Message(badPartSelect,text="Please select a partition.")
		badPartSelectMsg.pack()
		badPartSelectBtn = Button(badPartSelect, text="Close", command=badPartSelect.destroy)
		badPartSelectBtn.pack()
		return

	logger=open(logName.get(),'a')
	logger.write(getFormatTime() + "\n")
	logger.write("User accesses file system information\n\n")
	txtOutput.delete(1.0,END)

	txtOutput.insert(END,getFSInfo(vol,partDictStart[str(fsKey)]))
	logger.close()
	#fsstat -o dictionary.entry

btnFSinfo.config(command=btnFSinfoClick)

def btnDelFilesClick():
	if isAdvanced.get() is 1:
		txtOutput.delete(1.0,END)
		txtOutput.insert(END,"This will show you the deleted files on the selected partition")
		return

	vol = workingVolume.get()
	fsKey = workingPart.get()

	if fsKey == "":
		badPartSelect = Toplevel()
		badPartSelect.title("CrItIcAl ErRoR")
		badPartSelectMsg = Message(badPartSelect,text="Please select a partition.")
		badPartSelectMsg.pack()
		badPartSelectBtn = Button(badPartSelect, text="Close", command=badPartSelect.destroy)
		badPartSelectBtn.pack()
		return

	logger=open(logName.get(),'a')
	logger.write(getFormatTime() + "\n")
	logger.write("User accessed deleted files\n\n")
	
	entryFormat.set(1)
	txtOutput.delete(1.0,END)
	lstDelMft.delete(0,END)
	fileMessage.set("Deleted files:")
	txtOutput.insert(END,getDELitems(vol,partDictStart[str(fsKey)]))

	entryDict.clear()
	data = txtOutput.get(1.0, END) # gets all the text in the box
	usePattern = re.compile("[0-9]+:")
	matches = re.findall(usePattern, data)
	
	for x in matches:
		lstIndex = data.split().index(x)
		entryDict[x] = data.split()[lstIndex+1]
	
	for x,y in entryDict.items():
		lstDelMft.insert(END, x + " " + y)

	lblDELMFTintro.grid(row=5,column=2,sticky=W)
	lstDelMft.grid(row=6,column=2,rowspan=4,sticky=W+N+S)
	#btnHexFile.grid(row=6,column=3,sticky=W)
	#btnHashFile.grid(row=7,column=3,sticky=W)
	btnViewMetaData.grid(row=8,column=3,sticky=W)
	btnExtractFile.grid(row=9,column=3,sticky=W)

	logger.close()
	
btnDelFiles.config(command=btnDelFilesClick)

def btnMFTClick():
	if isAdvanced.get() is 1:
		txtOutput.delete(1.0,END)
		txtOutput.insert(END,"This will show you the MFT files on the selected partition.\nThese are the files listed in the Master File Table of the partition.")
		return

	vol = workingVolume.get()
	fsKey = workingPart.get()

	if fsKey == "":
		badPartSelect = Toplevel()
		badPartSelect.title("CrItIcAl ErRoR")
		badPartSelectMsg = Message(badPartSelect,text="Please select a partition.")
		badPartSelectMsg.pack()
		badPartSelectBtn = Button(badPartSelect, text="Close", command=badPartSelect.destroy)
		badPartSelectBtn.pack()
		return

	logger=open(logName.get(),'a')
	logger.write(getFormatTime() + "\n")
	logger.write("User accessed MFT entries\n\n")
	
	fileMessage.set("MFT files:")
	entryFormat.set(2)
	txtOutput.delete(1.0,END)
	lstDelMft.delete(0,END)

	txtOutput.insert(END,getMFTitems(vol,partDictStart[str(fsKey)]))

	entryDict.clear()
	data = txtOutput.get(1.0, END) # gets all the text in the box
	usePattern = re.compile("[0-9]+-[0-9]+-[0-9]+:")
	matches = re.findall(usePattern, data)
	
	for x in matches:
		lstIndex = data.split().index(x)
		entryDict[x] = data.split()[lstIndex+1]
	
	for x,y in entryDict.items():
		lstDelMft.insert(END, x + " " + y)
	lblDELMFTintro.grid(row=5,column=2,sticky=W)
	lstDelMft.grid(row=6,column=2,rowspan=4,sticky=W+N+S)
	#btnHexFile.grid(row=6,column=3,sticky=W)
	#btnHashFile.grid(row=7,column=3,sticky=W)
	btnViewMetaData.grid(row=8,column=3,sticky=W)
	btnExtractFile.grid(row=9,column=3,sticky=W)

	logger.close()

btnMFT.config(command=btnMFTClick)

def btnHexFileClick():
	fsKey = workingPart.get()
	vol = workingVolume.get()
	startOffset = partDictStart[str(fsKey)]
	eNum = entryNum.get()
	intopart = 0
	if int(eNum) is 0:
		intopart = (int(MFTent) * 16) + int(startOffset)
	else:
		intopart = (int(MFTent) * 16) + int(startOffset) + (int(eNum) * int(MFTent))
	txtOutput.delete(1.0,END)
	txtOutput.insert(END,getHex(vol, "1", str(intopart), MFTent))
btnHexFile.config(command=btnHexFileClick)

def btnHashFileClick():
	vol = workingVolume.get()
	fsKey = workingPart.get()
	eNum = entryNum.get()
	txtOutput.delete(1.0,END)
	txtOutput.insert(END,getMetaData(vol, partDictStart[str(fsKey)], eNum))
btnHashFile.config(command=btnHashFileClick)

def btnExtractFileClick():
	if isAdvanced.get() is 1:
		txtOutput.delete(1.0,END)
		txtOutput.insert(END,"This will pop up a new window with the advanced file options.")
		txtOutput.insert(END,"From this window, you will be able to extract files, hash them, and view their contents in hexidecimal")
		return

	logger=open(logName.get(),'a')
	logger.write(getFormatTime() + "\n")
	logger.write("User accessed advanced file features\n")
	btnExtractFile.config(state=DISABLED)

	vol = workingVolume.get()
	extractWindow = Toplevel()
	extractWindow.title("Advanced File Options")
	Label(extractWindow,text="Input file:\n" + vol).grid(row=0,column=0)
	Label(extractWindow,text="Block Size = ").grid(row=2,column=0,sticky=E)
	Label(extractWindow,text="Blocks to Skip = ").grid(row=3,column=0,sticky=E)
	Label(extractWindow,text="Blocks to Extract = ").grid(row=4,column=0,sticky=E)
	Label(extractWindow,text="Output File Name = ").grid(row=5,column=0,sticky=E)
	Label(extractWindow,text="Files are saved to /Investigations").grid(row=6,column=0,sticky=W)

	blockSize = StringVar()
	blockSkip = StringVar()
	blockExtract = StringVar()
	blockName = StringVar()

	bsEntry = Entry(extractWindow,textvariable=blockSize)
	skipEntry = Entry(extractWindow,textvariable=blockSkip)
	extractEntry = Entry(extractWindow,textvariable=blockExtract)
	fileNameEntry = Entry(extractWindow,textvariable=blockName)

	bsEntry.grid(row=2,column=1,sticky=E+W)
	skipEntry.grid(row=3,column=1,sticky=E+W)
	extractEntry.grid(row=4,column=1,sticky=E+W)
	fileNameEntry.grid(row=5,column=1,sticky=E+W)

	btnAdvExtract = Button(extractWindow,text="Extract File")
	btnAdvHash = Button(extractWindow,text="Hash File")
	btnAdvHex = Button(extractWindow,text="File Hex")
	btnAdvExit = Button(extractWindow,text="Exit Advanced Options")

	def btnAdvExtractClick():
		try:
			intTest1 = int(blockSize.get())
			intTest2 = int(blockSkip.get())
			intTest3 = int(blockExtract.get())
		except ValueError:
			badInt = Toplevel()
			badInt.title("CrItIcAl ErRoR")
			badIntMsg = Message(badInt,text="Please enter a valid number.")
			badIntMsg.pack()
			badIntBtn = Button(badInt, text="Close", command=badInt.destroy)
			badIntBtn.pack()
			return
		if blockName.get() == "":
			badFName = Toplevel()
			badFName.title("CrItIcAl ErRoR")
			badFNameMsg = Message(badFName,text="Please enter a file name.")
			badFNameMsg.pack()
			badFNameBtn = Button(badFName, text="Close", command=badFName.destroy)
			badFNameBtn.pack()
			return

		blockSizeX = blockSize.get()
		blockSizeX = blockSizeX.translate({ord(c): None for c in "`!:@#$%^&*()| "})

		blockSkipX = blockSkip.get()
		blockSkipX = blockSkipX.translate({ord(c): None for c in "`!:@#$%^&*()| "})

		blockExtractX = blockExtract.get()
		blockExtractX = blockExtractX.translate({ord(c): None for c in "`!:@#$%^&*()| "})

		formatFileName = blockName.get()
		formatFileName = formatFileName.translate({ord(c): None for c in "`!:@#$%^&*()| "})
		txtOutput.delete(1.0,END)
		txtOutput.insert(END,extractIntoFile(inFile=vol, outFile="/Investigations/" + formatFileName, bs=blockSizeX, skipAmt=blockSkipX, bNum=blockExtractX))
		txtOutput.insert(END,"File extracted")

		goodFileExtract = Toplevel()
		goodFileExtract.title("File Extraction")
		goodFileExtractMsg = Message(goodFileExtract,text="File extracted to /Investigations/" + formatFileName + ".")
		goodFileExtractMsg.pack()
		goodFileExtractBtn = Button(goodFileExtract, text="Close", command=goodFileExtract.destroy)
		goodFileExtractBtn.pack()

		logger.write(getFormatTime() + "\n")
		logger.write("User extracted file\n\n")

	def btnAdvHashClick():
		try:
			intTest1 = int(blockSize.get())
			intTest2 = int(blockSkip.get())
			intTest3 = int(blockExtract.get())
		except ValueError:
			badInt = Toplevel()
			badInt.title("CrItIcAl ErRoR")
			badIntMsg = Message(badInt,text="Please enter a valid number.")
			badIntMsg.pack()
			badIntBtn = Button(badInt, text="Close", command=badInt.destroy)
			badIntBtn.pack()
			return

		blockSizeX = blockSize.get()
		blockSizeX = blockSizeX.translate({ord(c): None for c in "`!:@#$%^&*()| "})

		blockSkipX = blockSkip.get()
		blockSkipX = blockSkipX.translate({ord(c): None for c in "`!:@#$%^&*()| "})

		blockExtractX = blockExtract.get()
		blockExtractX = blockExtractX.translate({ord(c): None for c in "`!:@#$%^&*()| "})

		formatFileName = blockName.get()
		formatFileName = formatFileName.translate({ord(c): None for c in "`!:@#$%^&*()| "})

		txtOutput.delete(1.0,END)

		if intHashType.get() is 1:
			txtOutput.insert(END,getMD5(vol, blockSizeX, blockSkipX, blockExtractX))
			data = txtOutput.get(1.0,END)
			splitData = data.split("=")
			logger.write("User performed MD5 hash on file:\n")
			logger.write(vol + " Block Size: " + blockSizeX + " Blocks Skipped: " + blockSkipX + " Blocks extracted: " + blockExtractX)
			logger.write(splitData[-1].upper() + "\n")
			txtOutput.insert(END,"MD5 Hash Performed")
		
		else:
			txtOutput.insert(END,getSHA1(vol, blockSizeX, blockSkipX, blockExtractX))
			data = txtOutput.get(1.0,END)
			splitData = data.split("=")
			logger.write("User performed SHA1 hash on file:\n")
			logger.write(vol + " Block Size: " + blockSizeX + " Blocks Skipped: " + blockSkipX + " Blocks extracted: " + blockExtractX)
			logger.write(splitData[-1].upper() + "\n")
			txtOutput.insert(END,"SHA1 Hash Performed")

	def btnAdvHexClick():
		try:
			intTest1 = int(blockSize.get())
			intTest2 = int(blockSkip.get())
			intTest3 = int(blockExtract.get())
		except ValueError:
			badInt = Toplevel()
			badInt.title("CrItIcAl ErRoR")
			badIntMsg = Message(badInt,text="Please enter a valid number.")
			badIntMsg.pack()
			badIntBtn = Button(badInt, text="Close", command=badInt.destroy)
			badIntBtn.pack()
			return

		blockSizeX = blockSize.get()
		blockSizeX = blockSizeX.translate({ord(c): None for c in "`!:@#$%^&*()| "})

		blockSkipX = blockSkip.get()
		blockSkipX = blockSkipX.translate({ord(c): None for c in "`!:@#$%^&*()| "})

		blockExtractX = blockExtract.get()
		blockExtractX = blockExtractX.translate({ord(c): None for c in "`!:@#$%^&*()| "})

		formatFileName = blockName.get()
		formatFileName = formatFileName.translate({ord(c): None for c in "`!:@#$%^&*()| "})

		txtOutput.delete(1.0,END)

		txtOutput.insert(END,returnCMD("dd if=" + vol + " bs=" + blockSizeX + " skip=" + blockSkipX + " count=" + blockExtractX + " | xxd"))
		logger.write(getFormatTime() + "\n")
		logger.write("User accessed file hex\n\n")
	#advanced file extraction window
	btnAdvExtract.config(command=btnAdvExtractClick)
	btnAdvHash.config(command=btnAdvHashClick)
	btnAdvHex.config(command=btnAdvHexClick)

	btnAdvExtract.grid(row=7,column=0)
	btnAdvHash.grid(row=7,column=1)
	btnAdvHex.grid(row=7,column=2)
	btnAdvExit.grid(row=8,columnspan=3,sticky=E+W)

	def btnExitAdvClick():
		try:
			logger.write(getFormatTime() + "\n")
			logger.write("User exited advanced file features\n\n")
			logger.close()
		except Exception:
			logger=open(logName.get(),'a')
			logger.write(getFormatTime() + "\n")
			logger.write("User exited advanced file features\n\n")
			logger.close()
		extractWindow.destroy()
		btnExtractFile.config(state=NORMAL)
		
		
	btnAdvExit.config(command=btnExitAdvClick)
	#btnAdvExit = Button(extractWindow,text="Exit Advanced Options",command=extractWindow.destroy)

btnExtractFile.config(command=btnExtractFileClick)

def btnViewMetaDataClick():
	if isAdvanced.get() is 1:
		txtOutput.delete(1.0,END)
		txtOutput.insert(END,"This will allow you to view the meta data of whichever entry is selected\nInformation included is the location of the data on the disk and its size, as well as how many times the location has been overwritten.\nCurrently, only the MFT files can be viewed in this manner\n\nMeta data information includes which clusters of the drive the data resides")
		return

	vol = workingVolume.get()
	fsKey = workingPart.get()
	eNum = entryNum.get()

	if eNum == "":
		badMetaSelect = Toplevel()
		badMetaSelect.title("CrItIcAl ErRoR")
		badMetaSelectMsg = Message(badMetaSelect,text="Please select a file.")
		badMetaSelectMsg.pack()
		badMetaSelectBtn = Button(badMetaSelect, text="Close", command=badMetaSelect.destroy)
		badMetaSelectBtn.pack()
		return

	logger=open(logName.get(),'a')
	logger.write(getFormatTime() + "\n")
	logger.write("User viewed metadata\n\n")
	
	txtOutput.delete(1.0,END)
	if entryFormat.get() is 2:
		txtOutput.insert(END,getMetaData(vol, partDictStart[str(fsKey)], eNum))
	else:
		txtOutput.insert(END,"Function not yet implemented")
	logger.close()

btnViewMetaData.config(command=btnViewMetaDataClick)

#move all frames for packing down here

idLabel.grid(row=0,sticky=W)
userEnter.grid(row=1,sticky=W)
txtImgPath.grid(row=2,columnspan=2,sticky=W)

btnGetImg.grid(row=3,sticky=W)

hashFrame.grid(row=1,column=1)
advancedFrame.grid(row=1,column=2)

codeFrame.grid(row=0,column=4,rowspan=1,sticky=W)

#pack this guy last!!
outputFrame.grid(row=3,column=4,rowspan=7)

#end of program
root.mainloop()
