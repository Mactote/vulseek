#!/usr/bin/python

"""
Vulseek project: A Vulnerability Finder for the x86 platform.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; version 2
of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

"""

###################################################################################################################################################

import re
import os
import sys
import copy
import string
import subprocess

sys.path.append(".")

###################################################################################################################################################

IGNORE_FUNCTIONS = ["call_gmon_start", "_start", "__i686.get_pc_thunk.bx", "__do_global_dtors_aux", "frame_dummy", "__libc_csu_init",
                    "__libc_csu_fini", "__do_global_ctors_aux", "__do_global_dtors_aux","__do_register_frame", "__do_deregister_frame",
                    "__libc_do_global_destruction", "__icrt_terminate", "__icrt_init", "__x86_jump_to_context", "__intel_cpu_indicator_init",
                    "__get_cpu_indicator", "__intel_set_fpx_mask", "__intel_new_proc_init", "__intel_proc_init", "__intel_sse2_", "__intel_sse4_",
                    "irc__get_msg", "irc__print", "extract64_lo", "extract64_hi"]

WARNING_FUNCTIONS = ["printf@", "strcpy"]


JUMP_MNEMONICS = ["call", "je", "jle", "jmp", "jnz", "jn", "jz", "jo", "jno", "js", "jns", "je", "jz", "jne", "jnz", 
                  "jb", "jnae", "jc", "jnb", "jae", "jnc", "jbe", "jna", "ja", "jnbe", "jl", "jnge", "jnl", "jng", 
                  "jg", "jnle", "jp", "jpe", "jnp", "jpo", "jcxz", "jecxz", "jg", "jge", "jle", "ret"]


###################################################################################################################################################

class CSection:
    
    name = None
    address = None
    data = None

class CBlock:
    
    name = None
    address = None
    lines = []
    
class CLine:
    
    address = None
    code = None
    function = None
    label = None
    comment = None
    
class CUsedVar:
    
    name = None
    address = None
    data = None
    ifnumber = None
    
###################################################################################################################################################

def getSymbolList(bin):     # We get a list of Global Symbols. Objdump does not substitute global vars names on the disassembly code and we want them to show the symbols used at first  

    global globalSymbols
    
    globalSymbols = {}
    stripped = False

    os.putenv("LANG", "C")  # We set ASCII as coded character for error messages and instructions, collating sequences, date formats, etc.
    cmd = "nm %s" % bin    # We use nm util to list symbols from the file if it is an object kind.
    
    cmdout = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    
    if (cmdout.stderr.read().find("no symbols") > -1):  # If there are just dynamic symbols
        stripped = True
        cmd = "objdump -TC %s" % bin
        cmdout = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    
    preSymbolsBuffer = cmdout.stdout.readlines()
    
    if stripped == False:
        for line in preSymbolsBuffer:
            
            line = line.replace("\t", " ").strip()
            line = line.split(" ")
            
            if len(line) > 2:   # Symbols with address defined
                address = hex(int(line[0], 16)).strip('L')
                name = line[2]
    
                globalSymbols[address] = name
    else:
        for line in preSymbolsBuffer:

            line = line.replace("\t", " ").strip()
            line = line.split(" ")
            
            if re.match("[a-f0-9]{8}", line[0]):   # Symbols with address defined
                if line[0] != "00000000":
                    address = hex(int(line[0], 16)).strip('L')
                    name = line[-1]
    
                    globalSymbols[address] = name

def getSection(bin, sectionName):   # Get data buffer of the given section

    os.putenv("LANG", "C")
    cmd = "objdump -s %s 2>/dev/null" % bin     # With -s option objdump displays full contents of all non-empty section
    dumpedFile = os.popen(cmd).readlines()

    buffer = []
    bStart = False

    for line in dumpedFile:
        line = line.strip()
        
        if line.lower().find("contents of section %s:" % sectionName) == 0 and bStart == False: # We save just data of the selected section
            bStart = True
        else:
            if bStart and line.lower().find("contents of section") == 0:
                break
            elif bStart:
                buffer.append(line)

    return parseSection(buffer, sectionName)

def parseSection(buffer, sectionName):  # We want to show constants, strings and global initialized vars in ascii code (not hexadecimal)
    
    Begin = False
    objSection = CSection()
    objSection.name = sectionName
    objSection.address                             
    objSection.data = ""

    for line in buffer:
        if line.find("  ") > -1:
            line = line[:line.find("  ")]
        elif line.find('\t') > -1:
            line = line[:line.find('\t')]
        elif line.find('\n') > -1:
            line = line[:line.find('\n')]
        line = line.split(" ")

        for x in line:
            if x == line[0]:
                if not Begin:
                    objSection.address = hex(int(x,16)).strip('L')     
                    Begin = True
            else:
                objSection.data += x

    objSection.data = objSection.data.decode("hex") # Convert data buffer from hex string to char string
    
    return objSection   # parseSection and so getSection returns a class with information of the given section

def getCode(bin, justImportant):

    os.putenv("LANG", "C")
    cmd = "objdump --prefix-addresses -d -Mintel %s 2>/dev/null" % bin # Get Disassembled Code. Display instructions in Intel syntax. 
    disassembledData = os.popen(cmd).readlines()

    started = False
    lines = []
    i = 0
    lastFunc = ""

    for line in disassembledData:
        i += 1
        line = line.strip()
        
        if line.find("section .text:") > -1:            # Executable code is in .text section
            started = True
            continue
        elif line.find("section .") > -1 and started:
            break
        elif not started:
            continue
        elif not re.match("[a-f0-9]{8}", line):
            continue
        
        x = parseCodeLine(line)
        
        if x.function == ".text":                       # If the binary is stripped, we look for the typical assembly prologue
            if x.code.replace(" ", "").replace("\t", "") == "pushebp":      
                if disassembledData[i].strip("\r").strip("\n").replace("\t", "").replace(" ", "").find("movebp,esp") > -1:   
                    x.function = "func_" + x.address
                    lastFunc = x.function
                elif lastFunc == "":
                    x.function = x.label
                    lastFunc = x.function                   
                else:
                    x.function = lastFunc            
            elif x.code.replace(" ", "").replace("\t", "").find("ret") > -1:
                if lastFunc == "":
                    x.function = x.label
                    lastFunc = ""
                else:
                    x.function = lastFunc
                    lastFunc = ""
            elif lastFunc == "":
                x.function = x.label
                lastFunc = x.function                   
            else:
                x.function = lastFunc

        if justImportant:                               # Omit uninteresting functions if we chose that option. Line is not saved in the buffer lines[]
            
            omit = 0
            for func in IGNORE_FUNCTIONS:
                if x.function.find(func) > -1:
                    omit = 1
                    break
            if not omit:
                lines.append(x)
        
        elif x.function != "Unknown":                                           # Include all lines/functions, except damaged lines
            lines.append(x)
    
    return lines


def parseCodeLine(asm):                             # ASM Line is parsed to get different parameters as address, instruction and function it belongs to
    
    objLine = CLine() 
    objLine.address = "0x" + asm[0:asm.find(" ")]
    
    p1 = asm.find("<")                              # objdump returns disassembly code with function names and addresses
    p2 = asm.find(">")
    p3 = asm.find("+", p1, p2)
    p4 = asm.find("-", p1, p2)
    
    if ((p1 == -1) or (p2 == -1)):                  # In case it is a damaged Line
        objLine.code = asm[asm.find(" ")+1:]
        objLine.function = "Unknown"
        objLine.label = objLine.address
    else:                                           # Normal line
        objLine.code = asm[p2+2:]
        objLine.label = asm[p1+1:p2]
        if p3 != -1:
            objLine.function = asm[p1+1:p3]
        elif p4 != -1:
            objLine.function = asm[p1+1:p4]
        else:
            objLine.function = objLine.label
   
    return objLine


def checkBinFile(bin):                              # If there is an error opening the file it exit with a message

    try:
        f = file(bin, "r")
        f.close()
    except:
        print "Error opening file %s" % bin
        print sys.exc_info()[1]
        sys.exit(1)

def parseASM(rodata, data, asm):                    # We save every function with its disassembled code and indicate constants, and global/local vars
    
    global globalSymbols
    global usedGlobalSymbols
    global usedVarsList
    
    usedGlobalSymbols = {}
    usedVarsList = {}
     
    blockList = []
    block = CBlock()
    
    for line in asm:                                # First loop to make the blocks and search vars
        
        if not block.name:                          # New block for a new function
            block.name = line.function
            block.address = line.address
        
        else:
            if block.name != line.function:         # Current line belongs to a new function
                blockList.append(block)
                
                block = CBlock()
                block.name = line.function
                block.address = line.address
                block.lines = []
        
        line = searchVars(line, rodata, data)                   # We search for Constants, Global and Local Vars in the line

        block.lines.append(line)
        
    blockList.append(block)
                    
    for block in blockList:                             # Second loop to replace names and values correctly
        if len(block.lines) == 0:                       # We needed a second loop to have the completed list of vars and to know if any var is a number or a string
            continue

        for line in block.lines:

            if line.comment:                            # We replace references with names and put possible values at the comments
                for x, item in usedVarsList.items():
                    if line.code.find(item.address) > -1:
                        line.code = line.code.replace(item.address, item.name)
                        line.comment = item.name
                        if item.data:               # If the symbol has constant data this is showed
                            for y, item2 in usedVarsList.items():
                                if y == x+4:
                                    if item.ifnumber:
                                        tmp = ""
                                        i = 3
                                        while i >= 0:
                                            tmp += item.ifnumber[i]
                                            i-= 1
                                        item.data = "0x" + tmp.encode("hex").upper() + '   or this string: ' + item.ifnumber    # We consider both possibilities (Number or string)
                                        break               
                            if not globalSymbols.has_key(hex(x).strip('L')):        # If it is a global var, not static,  only prints its name as comment
                                line.comment += ": " + item.data
                        break             
    
    return blockList


def searchVars(line, rodata, data):
    
    global globalSymbols
    global usedGlobalSymbols
    global usedVarsList
    
    res = re.findall("0x[a-f0-9]{6,8}", line.code, re.IGNORECASE)
    
    if res:
        for item in res:
            
            usedVar = CUsedVar()
            line.comment = False
            isglob = False
            
            if globalSymbols.has_key(hex(int(item, 16)).strip('L')):    # We check first if it is a Global Symbol (included Global Vars) to show used global vars at first
                isglob = True
                if not usedGlobalSymbols.has_key(hex(int(item, 16)).strip('L')):    # We list used global symbols.
                    usedGlobalSymbols[hex(int(item, 16)).strip('L')] = globalSymbols[hex(int(item, 16)).strip('L')]
                if not usedVarsList.has_key(int(item, 16)):
                    usedVar.name = globalSymbols[hex(int(item, 16)).strip('L')]     
                    usedVar.address = item
                    usedVar.data = ""
                line.comment = True
        
            if int(rodata.address, 16) <= int(item, 16) < int(rodata.address, 16)+len(rodata.data): # We check for strings and numeric constants
                if not usedVarsList.has_key(int(item, 16)):
                    if not isglob:
                        usedVar.name = "const_"+item
                        usedVar.address = item
                        usedVar.data = ""
                    index = int(item, 16)-int(rodata.address, 16)   # We want the relative address from section's buffer
                    usedVar.ifnumber = rodata.data[index:index+4]   # We just consider the posibility of an int number (4 bytes)
                    for c in rodata.data[index:]:                   # Or a string which would end with an "0x00" hex byte
                        if c != "\x00":
                            usedVar.data += c
                        else:
                            break
                                
                    usedVarsList[int(item, 16)] = usedVar
                line.comment = True
        
            if int(data.address, 16) <= int(item, 16) < int(data.address, 16)+len(data.data):   # We check for numeric initialized global vars
                
                if not usedVarsList.has_key(int(item, 16)):
                    if not isglob:                  # In case we'd want to expand compatibility to other compilers that not saved symbol's names
                        usedVar.name = "var_"+item  # Normally, if executable was compiled with GCC or ICC, Global Vars would have their own names
                        usedVar.address = item
                        usedVar.data = ""
                    index = int(item, 16)-int(data.address, 16)
                    usedVar.ifnumber = data.data[index:index+4]
                    for c in data.data[index:]:
                        if c != "\x00":
                            usedVar.data += c
                        else:
                            break
                                
                    usedVarsList[int(item, 16)] = usedVar
                line.comment = True
                    
            if not usedVarsList.has_key(int(item, 16)) and isglob:
                usedVarsList[int(item, 16)] = usedVar

    if re.match("call", line.code):         # We check if it is an API used and included in Global Symbol
        trap = re.findall("[a-f0-9]{8}", line.code, re.IGNORECASE)
        if trap:
            for item in trap:
                if globalSymbols.has_key(hex(int(item, 16)).strip('L')):    
                    tempi = re.findall("<.*?>", line.code)
                    for item2 in tempi:
                        line.code = line.code.replace(item2,"<%s>" % globalSymbols[hex(int(item, 16)).strip('L')])
    
    return line


def getVulBlock(asmBlock, x, riskyFunction):    # We prepared the buffer to print of the current vulnerable's block
    
    ##########################
    if riskyFunction == "printf@":
        if asmBlock.lines[x].comment:
            buffer = " %s:\t%s\t\t;%s" % (asmBlock.lines[x].address, asmBlock.lines[x].code.ljust(30), repr(asmBlock.lines[x].comment)) 
        else:
            buffer = " %s:\t%s" % (asmBlock.lines[x].address, asmBlock.lines[x].code.ljust(30))
        y = 1
        while re.search("movDWORDPTR\\[esp|push|leae(ax|bx|cx|dx|si|di),\\[ebp|move(ax|bx|cx|dx|si|di),", asmBlock.lines[x-y].code.replace(" ", "")) and y <= x:
            if asmBlock.lines[x-y].comment:
                buffer = " %s:\t%s\t\t;%s" % (asmBlock.lines[x-y].address, asmBlock.lines[x-y].code.ljust(30), repr(asmBlock.lines[x-y].comment)) + os.linesep + buffer
            else:
                buffer = " %s:\t%s" % (asmBlock.lines[x-y].address, asmBlock.lines[x-y].code.ljust(30)) + os.linesep + buffer
            y += 1
    
    ##########################
    if riskyFunction == "strcpy":
        if asmBlock.lines[x].comment:
            buffer = " %s:\t%s\t\t;%s" % (asmBlock.lines[x].address, asmBlock.lines[x].code.ljust(30), repr(asmBlock.lines[x].comment)) 
        else:
            buffer = " %s:\t%s" % (asmBlock.lines[x].address, asmBlock.lines[x].code.ljust(30))
        paramsPassed = 0
        throughReg = 0
        regUsed = {}
        regUsed[1] = None
        regUsed[2] = None
        y = 1
        while (paramsPassed < 2 or throughReg != 0) and y <= x:
            if re.search("_intel_", asmBlock.lines[x].code.replace(" ", ""), re.IGNORECASE):        # In case it is sse2 version of strcpy
                if re.search("move(c|d)x,|leae(c|d)x,", asmBlock.lines[x-y].code.replace(" ", ""), re.IGNORECASE):
                    paramsPassed += 1
            
            elif re.search("movDWORDPTR\\[esp|push", asmBlock.lines[x-y].code.replace(" ", ""), re.IGNORECASE):
                paramsPassed += 1
                if re.search("movDWORDPTR\\[esp\S*\\],e(ax|bx|cx|dx|si|di)|pushe(ax|bx|cx|dx|si|di)", asmBlock.lines[x-y].code.replace(" ", ""), re.IGNORECASE):
                    throughReg += 1     # We count params passed by register. We will look for values passed to register previously.
                    commaRef = asmBlock.lines[x-y].code.find(",")       # We want to save which register was used
                    if commaRef > -1:
                        regUsed[throughReg] = asmBlock.lines[x-y].code[commaRef+1:]     # In case it is a mov instruction
                    else:
                        regUsed[throughReg] = asmBlock.lines[x-y].code.replace(" ", "")[4:]     # In case it is a push instruction
  
                                     
            elif throughReg != 0 and re.search("move(ax|bx|cx|dx|si|di),|leae(ax|bx|cx|dx|si|di),", asmBlock.lines[x-y].code.replace(" ", ""), re.IGNORECASE): # We check for values passed to registers used in strcpy
                if regUsed[2] != None and re.search(regUsed[2], asmBlock.lines[x-y].code.replace(" ", ""), re.IGNORECASE):
                    throughReg -= 1
                    regUsed[2] = None
                elif regUsed[1] != None and re.search(regUsed[1], asmBlock.lines[x-y].code.replace(" ", ""), re.IGNORECASE):
                    throughReg -= 1
                    regUsed[1] = None
            
            if asmBlock.lines[x-y].comment:
                buffer = " %s:\t%s\t\t;%s" % (asmBlock.lines[x-y].address, asmBlock.lines[x-y].code.ljust(30), repr(asmBlock.lines[x-y].comment)) + os.linesep + buffer
            else:
                buffer = " %s:\t%s" % (asmBlock.lines[x-y].address, asmBlock.lines[x-y].code.ljust(30)) + os.linesep + buffer    
            
            y += 1
    
    return buffer

def printScan(bin, blockList, showdisass, showrep):

    global usedGlobalSymbols
    global usedVarsList

    hits = 0
    newBranch = 0
    repbuffer = ""
    disassbuffer = ""
    disassbuffer += os.linesep

    print
    print "#########################################################################"
    print "# File generated by Vulseek - Vulnerability Finder for the x86 platform #"
    print "#########################################################################"
    print
    
    disassbuffer += "###########################" + "%s" % "#"*len(bin) + os.linesep
    disassbuffer += "# Disassembly code for '%s' #" %  bin + os.linesep
    disassbuffer += "###########################" + "%s" % "#"*len(bin) + os.linesep*2

    if len(usedGlobalSymbols) > 0:
        disassbuffer += "Global Vars:" + os.linesep*2
        for address in usedGlobalSymbols:
            if usedVarsList[int(address, 16)].data != "":
                disassbuffer += " 0x%s:\t%s\t; Initial Value: %s" % (address.lstrip("0x").zfill(8), usedGlobalSymbols[address].ljust(25), repr(usedVarsList[int(address, 16)].data)) + os.linesep
            else:
                disassbuffer +=  " 0x%s:\t%s" % (address.lstrip("0x").zfill(8), usedGlobalSymbols[address].ljust(25)) + os.linesep
        disassbuffer += os.linesep

    for block in blockList:                 # We show Disassembly code/analyze it function by function
        if len(block.lines) == 0:
            continue
        
        i = -1   # Index for actual line into the actual function

        disassbuffer += "sub %s:" % block.name + os.linesep*2   # Function's beginning
        
        for line in block.lines:
            
            i += 1
            if line.code == "nop":      # "nop" instructions are not showed
                continue
            
            if newBranch:
                disassbuffer += os.linesep + " %s:" % line.label + os.linesep
                newBranch = 0

            if line.comment:              
                buf = " %s:\t%s\t\t;%s" % (line.address, line.code.ljust(30), repr(line.comment)) 
            else:
                buf = " %s:\t%s" % (line.address, line.code.ljust(30))
                
            disassbuffer += buf + os.linesep

            mnemonic = line.code.split(" ")[0]

            if JUMP_MNEMONICS.__contains__(mnemonic):       # Disassembly is showed with each branch block separately
                newBranch = 1
                if showrep and mnemonic == "call":
                    for riskyFunc in WARNING_FUNCTIONS:     # In this part we look for vulnerabilities 
                        if line.code.find(riskyFunc) > -1:
                            
                            ##########################
                            if riskyFunc == "printf@":
                                if i > 1:
                                    if re.search("movDWORDPTR\\[esp\\],e(ax|bx|cx|dx|si|di)|pushe(ax|bx|cx|dx|si|di)", block.lines[i-1].code.replace(" ", "")):     # If there is a parameter passed to the stack through a register
                                        if re.search("move(ax|bx|cx|dx|si|di),const_", block.lines[i-2].code.replace(" ", "")):     # and it seems to be a constant format string
                                            colon = block.lines[i-2].comment.find(":")
                                            if colon > -1:
                                                specifiers = re.findall("%[csduoxefgXEGpnDUOF]", block.lines[i-2].comment[colon:])  # We look for format specifiers and count them to compare with the rest of the params passed
                                                numSpecifiers = len(specifiers)
                                                z = 3
                                                numParams = 0
                                                while re.search("movDWORDPTR\\[esp|push|leae(ax|bx|cx|dx|si|di),\\[ebp|move(ax|bx|cx|dx|si|di),", block.lines[i-z].code.replace(" ", "")) and z <= i: # We just check for prior instructions which manipulate the params passed to printf
                                                    if re.search("movDWORDPTR\\[esp|push", block.lines[i-z].code.replace(" ", "")):
                                                        numParams += 1
                                                    z += 1
                                                if numSpecifiers != numParams:
                                                    hits += 1
                                                    buf2 = getVulBlock(block, i, riskyFunc)
                                                    repbuffer += os.linesep +  " %d) Check the usage of %s in function %s:" % (hits, riskyFunc, line.function) + os.linesep*2 + buf2 + os.linesep*2
                                                        
                                                    if numSpecifiers > numParams:
                                                        repbuffer +=  " Warning: Format string contains more format specifiers than params have been passed to printf. There is a FS vulnerability." + os.linesep*2
                                                    elif numSpecifiers < numParams:
                                                        repbuffer +=  " Warning: Format string contains less format specifiers than params have been passed to printf. There is a FS vulnerability." + os.linesep*2
            
                                        elif re.search("move(ax|bx|cx|dx|si|di),|leae(ax|bx|cx|dx|si|di),", block.lines[i-2].code.replace(" ", "")):        # and it doesn´t seem to be a constant format string
                                            hits += 1
                                            buf2 = getVulBlock(block, i, riskyFunc)
                                            repbuffer += os.linesep +  " %d) Check the usage of %s in function %s:" % (hits, riskyFunc, line.function) + os.linesep*2 + buf2 + os.linesep*2
                                            if re.search("\\[ebp", block.lines[i-2].code.replace(" ", "")):
                                                repbuffer += " Warning: First parameter of the printf call is not a constant format string. There is a potential FS vulnerability." + os.linesep*2
                                            else:
                                                repbuffer += " Warning: First parameter of the printf call does not seem to be a constant format string. It could be a potential FS vulnerability." + os.linesep*2
                                    
                                    elif block.lines[i-1].comment and re.search("movDWORDPTR\\[esp\\],|push", block.lines[i-1].code.replace(" ", "")) and block.lines[i-1].comment.find("const_") == -1:    # In case the first parameter is not passed through a register and it doesn´t seem to be a constant format string
                                        hits += 1
                                        buf2 = getVulBlock(block, i, riskyFunc)
                                        repbuffer += os.linesep +  " %d) Check the usage of %s in function %s:" % (hits, riskyFunc, line.function) + os.linesep*2 + buf2 + os.linesep*2
                                        repbuffer += " Warning: First parameter of the printf call does not seem to be a constant format string. It could be a potential FS vulnerability." + os.linesep*2
                                    
                                    elif re.search("movDWORDPTR\\[esp\\],const_|pushconst_", block.lines[i-1].code.replace(" ", "")):       # In case the first parameter is not passed through a register and it seems to be a constant format string 
                                        colon = block.lines[i-1].comment.find(":")
                                        if colon > -1:
                                            specifiers = re.findall("%[csduoxefgXEGpnDUOF]", block.lines[i-1].comment[colon:])      # We look for format specifiers and count them to compare with the rest of the params passed
                                            numSpecifiers = len(specifiers)
                                            z = 2
                                            numParams = 0
                                            while re.search("movDWORDPTR\\[esp|push|leae(ax|bx|cx|dx|si|di),\\[ebp|move(ax|bx|cx|dx|si|di),", block.lines[i-z].code.replace(" ", "")) and z <= i:
                                                if re.search("movDWORDPTR\\[esp|push", block.lines[i-z].code.replace(" ", "")):
                                                    numParams += 1
                                                z += 1
                                            if numSpecifiers != numParams:
                                                hits += 1
                                                buf2 = getVulBlock(block, i, riskyFunc)
                                                repbuffer += os.linesep +  " %d) Check the usage of %s in function %s:" % (hits, riskyFunc, line.function) + os.linesep*2 + buf2 + os.linesep*2
                                                    
                                                if numSpecifiers > numParams:
                                                    repbuffer +=  " Warning: Format string contains more format specifiers than params have been passed to printf. There is a potential FS vulnerability." + os.linesep*2
                                                elif numSpecifiers < numParams:
                                                    repbuffer +=  " Warning: Format string contains less format specifiers than params have been passed to printf. There is a potential FS vulnerability." + os.linesep*2
        
                            ##########################
                            if riskyFunc == "strcpy":
                                if i > 1:
                                    lenCheck = None
                                    validCheck = None
                                    z = 0
                                    while z <= i and not lenCheck:
                                        z += 1
                                        if re.search("call[a-f0-9]{8}<\S*strlen", block.lines[i-z].code.replace(" ", ""), re.IGNORECASE):
                                            lenCheck = True
                                    if lenCheck:            # At least, strlen is used in this function
                                        varChecked = None
                                        commaRef = None
                                        y = z
                                        if re.search("_intel_", block.lines[i-z].code.replace(" ", ""), re.IGNORECASE):
                                            while varChecked == None and y <= i:
                                                if re.search("movedx,|leaedx,", block.lines[i-y].code.replace(" ", ""), re.IGNORECASE):
                                                    commaRef = block.lines[i-y].code.replace(" ", "").find(",")
                                                    varChecked = block.lines[i-y].code.replace(" ", "")[commaRef+1:]
                                                y += 1
                                        else:
                                            while varChecked == None and y <= i:
                                                if re.search("movDWORDPTR\\[esp\S*\\],e(ax|bx|cx|dx|si|di)|pushe(ax|bx|cx|dx|si|di)", block.lines[i-y].code.replace(" ", ""), re.IGNORECASE):
                                                    while varChecked == None and y <= i:
                                                        y += 1
                                                        if re.search("move(ax|bx|cx|dx|si|di),|leae(ax|bx|cx|dx|si|di),", block.lines[i-y].code.replace(" ", ""), re.IGNORECASE):
                                                            commaRef = block.lines[i-y].code.replace(" ", "").find(",")
                                                            varChecked = block.lines[i-y].code.replace(" ", "")[commaRef+1:]
                                                elif re.search("movDWORDPTR\\[esp|push", block.lines[i-y].code.replace(" ", ""), re.IGNORECASE):
                                                    commaRef = block.lines[i-y].code.replace(" ", "").find(",")
                                                    if commaRef > -1:
                                                        varChecked = block.lines[i-y].code.replace(" ", "")[commaRef+1:]
                                                    else:
                                                        varChecked = asmBlock.lines[i-y].code.replace(" ", "")[4:]
                                                y += 1

                                        if varChecked:      # When we have the variable passed to strlen we check if it is used as parameter of strcpy
                                            paramsPassed = 0
                                            throughReg = 0
                                            regUsed = {}
                                            regUsed[1] = None
                                            regUsed[2] = None
                                            y = 1
                                            while (paramsPassed < 2 or throughReg != 0) and y <= i:
                                                if re.search(re.escape(varChecked), block.lines[i-y].code.replace(" ", ""), re.IGNORECASE):
                                                    validCheck = True
                                                
                                                if re.search("_intel_", block.lines[i].code.replace(" ", ""), re.IGNORECASE):        # In case it is sse2 version of strcpy
                                                    if re.search("move(c|d)x,|leae(c|d)x,", block.lines[i-y].code.replace(" ", ""), re.IGNORECASE):
                                                        paramsPassed += 1
                                                
                                                elif re.search("movDWORDPTR\\[esp|push", block.lines[i-y].code.replace(" ", ""), re.IGNORECASE):
                                                    paramsPassed += 1
                                                    if re.search("movDWORDPTR\\[esp\S*\\],e(ax|bx|cx|dx|si|di)|pushe(ax|bx|cx|dx|si|di)", block.lines[i-y].code.replace(" ", ""), re.IGNORECASE):
                                                        throughReg += 1
                                                        commaRef = block.lines[i-y].code.find(",")
                                                        if commaRef > -1:
                                                            regUsed[throughReg] = block.lines[i-y].code[commaRef+1:]
                                                        else:
                                                            regUsed[throughReg] = block.lines[i-y].code.replace(" ", "")[4:]
                                    
                                                elif throughReg != 0 and re.search("move(ax|bx|cx|dx|si|di),|leae(ax|bx|cx|dx|si|di),", block.lines[i-y].code.replace(" ", ""), re.IGNORECASE):
                                                    if regUsed[2] != None and re.search(regUsed[2], block.lines[i-y].code.replace(" ", ""), re.IGNORECASE):
                                                        throughReg -= 1
                                                        regUsed[2] = None
                                                    elif regUsed[1] != None and re.search(regUsed[1], block.lines[i-y].code.replace(" ", ""), re.IGNORECASE):
                                                        throughReg -= 1
                                                        regUsed[1] = None   
                                                
                                                y += 1
                                            
                                            
                                    if not validCheck:      # If any strcpy's parameter was not checked with strlen function, strcpy seems to have been used badly
                                        hits += 1
                                        buf2 = getVulBlock(block, i, riskyFunc)
                                        repbuffer += os.linesep +  " %d) Check the usage of %s in function %s:" % (hits, riskyFunc, line.function) + os.linesep*2 + buf2 + os.linesep*2
                                    
                                        repbuffer += " Warning: There is no lenght check and consequently there is a potential BOF vulnerability." + os.linesep*2


        disassbuffer += "end sub;" + os.linesep*2    # Function's end
    
    if showdisass:              # We have disassembly code so if it was chosen we could print it.
        print disassbuffer 

    if showrep:
        print
        print "#############################################" + "%s" % "#"*len(bin)
        print "# Report of probable vulnerabilities for '%s' #" %  bin
        print "#############################################" + "%s" % "#"*len(bin)
        print
        if hits == 0:
            print "There were not found any vulnerabilies"
        else:
            print repbuffer
        print


def vulseek(bin, showdisass, showrep, justImportant):

    checkBinFile(bin)                                       #Checks if the binary file is opened correctly.
    getSymbolList(bin)                                      #Obtains the symbol list
    rawRoData = getSection(bin, ".rodata")                  #Checks if there is read only data (strings, constants)
    rawData = getSection(bin, ".data")                      #Checks if there are global initialized vars
    rawDisassemble = getCode(bin, justImportant)            #Gets the raw disassemble code.
    asm = parseASM(rawRoData, rawData, rawDisassemble)      #Parses the code with every data
    printScan(bin, asm, showdisass, showrep)                #Shows the disassemble code and report of vulnerabilities depending on the options chosen

def usage():
    print "Vulseek - Vulnerability Finder for the x86 platform."
    print
    print "Usage:"
    print sys.argv[0], "[options] <binary file>"
    print
    print "Options:"
    print " -d\t\tJust disassemble the file"
    print " -a\t\tShow both complete disassembly and report of dangerous functions"
    print " -i\t\tAnalyze only interesting functions"
    print "   \t\t(A report of dangerous functions is generated by default)"
    print

def main():

    binaryFile = None
    disassemble = False
    report = True
    justImp = False

    if len(sys.argv) == 1:
        usage()
        sys.exit(0)

    for arg in sys.argv[1:]:                    # Reading the options chosen
        if arg[0] == "-": 
            if len(arg) > 1:
                if arg[1] == "a":
                    disassemble = True
                    report = True
                elif arg[1] == "d":
                    disassemble = True
                    report = False
                elif arg[1] == "i":
                    justImp = True
        elif not binaryFile:
            binaryFile = arg
        else:
            usage()                             #If there was not passed any bin to the program It shows the usage
            sys.exit(0)

    if not binaryFile:
        usage()
        sys.exit(0)

    vulseek(binaryFile, disassemble, report, justImp)

if __name__ == "__main__":
    main()
