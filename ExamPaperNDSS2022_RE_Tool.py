# Reverse engineering package targetted for exam protoctoring suites.
# Radare2 wrapper

import r2pipe
import argparse
import sys
import re

def parseArgs():
    parser = argparse.ArgumentParser(description='Reverse engineering package designed for analysing exam proctoring suites.')

    parser.add_argument('binary', metavar='binary', nargs='+',
                        help='path to the binary to analyze')
    parser.add_argument('--cfg', dest='cfg', action='store_true',
                        help='print CFG of found functions (default: false)')
    parser.add_argument('--pdd', dest='pdd', action='store_true',
                        help='attempt to decompile found functions using Ghirda (default: false require)')
    parser.add_argument('--segments', dest='segments', action='store_true',
                        help='print the different code segment boundaries (default: false)')
    parser.add_argument('--vm', dest='vm', action='store_true',
                        help='highlight virtual machine detection code segments (default: false)')
    parser.add_argument('--webcam', dest='webcam', action='store_true',
                        help='highlight webcam related code segments (default: false)')
    parser.add_argument('--microphone', dest='microphone', action='store_true',
                        help='highlight microphone related code segments (default: false)')
    parser.add_argument('--insecureHttp', dest='insecureHttp', action='store_true',
                        help='highlight insecure http URLs being used in the binary (default: false)')
    parser.add_argument('--encryption', dest='encryption', action='store_true',
                        help='highlight encryption related code segments and attempt to extract their keys (default: false)')
    parser.add_argument('--liveMemory', dest='liveMemory', action='store_true',
                        help='execute the binary with a gdb hook for a more comprehensive analysis (default: false)')
    parser.add_argument('--summary', dest='summary', action='store_true',
                        help='produce a high level summary of the above analysis (default: false)')
    return parser.parse_args()

class R2Error(RuntimeError):
    pass

class ExamPaperR2:

    SUPPORTED_ARCHS = ["arm", "x86"]
    VIRTUAL_MACHINE_VENDORS = ["vmware", "innotek", "parallels", "qemu", "virtual machine", "virtualmachine", "hyperv", "virtualpc", "virtualbox"]
    CAMERA_VENDORS = ["webcam", "camera", "manycam", "webcamoid", "vcam", "lightstream"]
    MICROPHONE_VENDORS = ["microphone", "virtual microphone", "virtualmic"]
    SUPPORTED_BINTYPES = ["elf", "pe", "mach0"]

    def __init__(self, _file, _cfg, _pdd):
        self.file = _file
        #self.logging = _logging
        self.r2 = None
        self.analyzed = False
        self.cfg = _cfg
        self.pdd = _pdd
        self.encryption = list()
        self.summary = False
        self.summaryResults = dict()

    def log(self, log_msg, *args, **kwargs):
        print("\033[92m" + log_msg + "\033[0m", *args, **kwargs, file=sys.stderr)

    def load(self):
        """
        Opens the r2pipe session.
        R2Error may be thrown if there is an error loading.
        Reference: https://github.com/CarveSystems/gostringsr2/blob/master/gostringsr2/gostringsr2.py
        """
        self.log("Loading file into r2: {}".format(self.file))
        self.r2 = r2pipe.open(self.file)
        self.data = {}
        self.data["info"] = self.runR2JsonCmd("ij")
        if "bin" not in self.data["info"]:
            raise R2Error("r2 could not parse the binary")

        self.arch = self.data["info"]["bin"]["arch"]
        self.bintype = self.data["info"]["bin"]["bintype"]
        self.bits = self.data["info"]["bin"]["bits"]
        self.binos = self.data["info"]["bin"]["os"]

        if self.bintype not in ["elf", "mach0", "pe"]:
            raise R2Error(
                "bintype {} not supported by gostringsr2. Supported: {}".format(
                    self.bintype, ExamPaperR2.SUPPORTED_BINTYPES
                )
            )
        if self.arch not in ["arm", "x86"]:
            self.log("warning: arch {} may not fully work".format(self.arch))

        self.data["symbols"] = self.runR2JsonCmd("isj")
        self.data["sections"] = self.runR2JsonCmd("iSj")

        self.loaded = True

        self.log(self.file_info())
    
    def file_info(self):
        """
        Returns a descriptive string of the loaded binary.
        Reference: https://github.com/CarveSystems/gostringsr2/blob/master/gostringsr2/gostringsr2.py
        """

        if self.loaded:
            return (
                "file: {}\n"
                "size: {} KB\n"
                "executable: {}\n"
                "language: {}\n"
                "architecture: {}-bit {}\n"
                "os: {}\n"
                "stripped: {}\n".format(
                    self.data["info"]["core"]["file"],
                    self.data["info"]["core"]["size"] // 1024,
                    self.data["info"]["bin"]["bintype"],
                    self.data["info"]["bin"]["lang"],
                    self.data["info"]["bin"]["bits"],
                    self.data["info"]["bin"]["arch"],
                    self.data["info"]["bin"]["os"],
                    self.data["info"]["bin"]["stripped"],
                )
            )

        return "file: <none>"

    def runR2Cmd(self, cmd):
        try: 
            output = self.r2.cmd(cmd)
        except:
            raise R2Error("failed to run " + cmd + " error: " + output)
        return output
    
    def runR2JsonCmd(self, cmd):
        try: 
            output = self.r2.cmdj(cmd)
        except:
            raise R2Error("failed to run " + cmd + " error: " + output)
        return output

    def autoAnalysis(self):
        if self.analyzed:
            return 
        self.analyzed = True
        return self.runR2Cmd("aaa")

    def symbols(self):
        return self.runR2Cmd("iS")

    def findString(self, string):
        try: 
            rawStringIzz = self.runR2Cmd("izz")
            rawStringIzz = re.sub(' +', ' ', rawStringIzz)
            rawStringIzz = rawStringIzz.split("\n")
            parsedStringIzz = list()
            for line in rawStringIzz:
                parsedStringIzz.append(line.split(" ", 7))
            cleanedList = list()
            for index in range(len(parsedStringIzz)):
                if len(parsedStringIzz[index]) != 8:
                    continue
                cleanedList.append(parsedStringIzz[index])

            output = list()
            for index in range(len(cleanedList)):
                if string.upper() in cleanedList[index][7].upper():
                    dictLine = dict()
                    dictLine["vaddr"] = cleanedList[index][2]
                    dictLine["section"] = cleanedList[index][5]
                    dictLine["type"] = cleanedList[index][6]
                    dictLine["string"] = cleanedList[index][7]
                    dictLine["len"] = int(cleanedList[index][3])

                    output.append(dictLine)
            
            if len(output) == 0:
                rawSearch = self.runR2Cmd("/i " + string)
                splitLine = string.split("\n")
                for line in splitLine:
                    lineList = list()
                    dictLine = dict()
                    lineList = line.split(" ", 2)
                    if len(lineList) == 3:
                        dictLine["vaddr"] = lineList[0]
                        dictLine["section"] = ".data"
                        dictLine["type"] = "utf8"
                        dictLine["string"] = lineList[2]
                        dictLine["len"] = len(lineList[2])

                        output.append(dictLine)
        except:
            raise R2Error("failed to find strings")
        return output

    def findCryptoKeys(self):
        try: 
            rawStringIzz = self.runR2Cmd("izz")
            rawStringIzz = re.sub(' +', ' ', rawStringIzz)
            rawStringIzz = rawStringIzz.split("\n")
            parsedStringIzz = list()
            for line in rawStringIzz:
                parsedStringIzz.append(line.split(" ", 7))
            cleanedList = list()
            for index in range(len(parsedStringIzz)):
                if len(parsedStringIzz[index]) != 8:
                    continue
                cleanedList.append(parsedStringIzz[index])

            output = list()
            for index in range(len(cleanedList)):
                dictLine = dict()

                if "AES_" in cleanedList[index][7].upper():
                    dictLine["algorithm"] = "AES"
                elif "DES_" in cleanedList[index][7].upper():
                    dictLine["algorithm"] = "DES" 
                elif "SECRET" in cleanedList[index][7].upper():
                    dictLine["algorithm"] = "Unknown"               
                else: 
                    continue

                dictLine["potentialKeys"] = list()
                if index > 20:
                    for subindex in range(index-20, index):
                        if cleanedList[subindex][3] == '16':
                            dictLine["potentialKeys"].append(cleanedList[subindex][7])
                        if cleanedList[subindex][3] == '32':
                            dictLine["potentialKeys"].append(cleanedList[subindex][7])
                if (index + 20) < len(cleanedList):
                    for subindex in range(index, (index + 20)):
                        if cleanedList[subindex][3] == '16':
                            dictLine["potentialKeys"].append(cleanedList[subindex][7])   
                        if cleanedList[subindex][3] == '32':
                            dictLine["potentialKeys"].append(cleanedList[subindex][7])         

                dictLine["vaddr"] = cleanedList[index][2]
                dictLine["section"] = cleanedList[index][5]
                dictLine["type"] = cleanedList[index][6]
                dictLine["string"] = cleanedList[index][7]
                dictLine["len"] = int(cleanedList[index][3])

                output.append(dictLine)
        except:
            raise R2Error("failed to find strings")
        return output


    def findXrefs(self, vaddr):
        return self.runR2Cmd("axt @ " + vaddr)

    def parseXrefs(self, string):
        try:
            output = list()
            splitLine = string.split("\n")

            for line in splitLine:
                output.append(line.split(" ", 3))

            return output
        except:
            raise R2Error("error parsing search")

    def funcCFG(self, func):
        return self.runR2Cmd("pdf 1 @ " + func)

    def funcPDD(self, func):
        if self.analyzed == False:
            self.autoAnalysis()
        return self.runR2Cmd("pdda @ " + func)

    def findVMs(self):
        try:
            if self.analyzed == False:
                self.autoAnalysis()

            functions = dict()
            noFunc = list()

            for vendor in ExamPaperR2.VIRTUAL_MACHINE_VENDORS:
                vendorSearch = self.findString(vendor)
                if len(vendorSearch) == 0:
                    continue

                for line in vendorSearch:
                    vaddr = line["vaddr"]
                    rawXrefs = self.findXrefs(vaddr)
                    if len(rawXrefs) == 0:
                        noFunc.append(line)
                        continue

                    xrefs = self.parseXrefs(rawXrefs)
                    for xref in xrefs:
                        if len(xref) <= 1:
                            continue
                        if xref[0] == "(nofunc)":
                            line["xref"] = xref[3]
                            noFunc.append(line)
                            continue
                        functions[xref[0]] = xref[1]

            if self.summary:
                if len(functions) == 0:
                    if len(noFunc) == 0:
                        self.summaryResults["VirtualM Detection"] = False
                        return
                self.summaryResults["VirtualM Detection"] = True
                return
            if len(functions) == 0:
                if len(noFunc) == 0:
                    self.log("No virtual machine detection found!")
                else:
                    self.log("Evidence of virtual machine detection found, however no function references can be automatically found!")
                    if len(noFunc) != 0:
                        for line in noFunc:
                            if "xref" in line.keys():
                                self.log("\t vaddr: " + line["vaddr"] + "\t xref: " + line["xref"] + " \t section: " + line["section"] + "\t type: " + line["type"] + " \t string: " + line["string"])
                            else:
                                self.log("\t vaddr: " + line["vaddr"] + " \t section: " + line["section"] + "\t type: " + line["type"] + " \t string: " + line["string"])

            for function in functions.keys():
                self.log("Virtual machine detection found!  \n \t name: " + function + " vaddr: " + functions[function])
                if self.cfg:
                    self.log(self.funcCFG(function))
                if self.pdd:
                    self.log(self.funcPDD(function))
        except:
            raise R2Error("error virtual machine detection")

    def findCameraBindings(self):
        try:
            if self.analyzed == False:
                self.autoAnalysis()

            functions = dict()
            noFunc = list()

            for vendor in ExamPaperR2.CAMERA_VENDORS:
                vendorSearch = self.findString(vendor)
                if len(vendorSearch) == 0:
                    continue

                for line in vendorSearch:
                    vaddr = line["vaddr"]
                    rawXrefs = self.findXrefs(vaddr)
                    if len(rawXrefs) == 0:
                        noFunc.append(line)
                        continue

                    xrefs = self.parseXrefs(rawXrefs)
                    for xref in xrefs:
                        if len(xref) <= 1:
                            continue
                        if xref[0] == "(nofunc)":
                            line["xref"] = xref[3]
                            noFunc.append(line)
                            continue
                        functions[xref[0]] = xref[1]

            if self.summary:
                if len(functions) == 0:
                    if len(noFunc) == 0:
                        self.summaryResults["Camera Detection"] = False
                        return
                self.summaryResults["Camera Detection"] = True
                return
            if len(functions) == 0:
                if len(noFunc) == 0:
                    self.log("No camera detection found!")
                else:
                    self.log("Evidence of camera detection found, however no function references can be automatically found!")
                    if len(noFunc) != 0:
                        for line in noFunc:
                            if "xref" in line.keys():
                                self.log("\t vaddr: " + line["vaddr"] + "\t xref: " + line["xref"] + " \t section: " + line["section"] + "\t type: " + line["type"] + " \t string: " + line["string"])
                            else:
                                self.log("\t vaddr: " + line["vaddr"] + " \t section: " + line["section"] + "\t type: " + line["type"] + " \t string: " + line["string"])

            for function in functions.keys():
                self.log("Camera detection found!  \n \t name: " + function + " vaddr: " + functions[function])
                if self.cfg:
                    self.log(self.funcCFG(function))
                if self.pdd:
                    self.log(self.funcPDD(function))
        except:
            raise R2Error("error camera detection")

    def findMicrophoneBindings(self):
        try:
            if self.analyzed == False:
                self.autoAnalysis()

            functions = dict()
            noFunc = list()

            for vendor in ExamPaperR2.MICROPHONE_VENDORS:
                vendorSearch = self.findString(vendor)
                if len(vendorSearch) == 0:
                    continue

                for line in vendorSearch:
                    vaddr = line["vaddr"]
                    rawXrefs = self.findXrefs(vaddr)
                    if len(rawXrefs) == 0:
                        noFunc.append(line)
                        continue

                    xrefs = self.parseXrefs(rawXrefs)
                    for xref in xrefs:
                        if len(xref) <= 1:
                            continue
                        if xref[0] == "(nofunc)":
                            line["xref"] = xref[3]
                            noFunc.append(line)
                            continue
                        functions[xref[0]] = xref[1]

            if self.summary:
                if len(functions) == 0:
                    if len(noFunc) == 0:
                        self.summaryResults["Microphone Detection"] = False
                        return
                self.summaryResults["Microphone Detection"] = True
                return
            if len(functions) == 0:
                if len(noFunc) == 0:
                    self.log("No microphone detection found!")
                else:
                    self.log("Evidence of microphone detection found, however no function references can be automatically found!")
                    if len(noFunc) != 0:
                        for line in noFunc:
                            if "xref" in line.keys():
                                self.log("\t vaddr: " + line["vaddr"] + "\t xref: " + line["xref"] + " \t section: " + line["section"] + "\t type: " + line["type"] + " \t string: " + line["string"])
                            else:
                                self.log("\t vaddr: " + line["vaddr"] + " \t section: " + line["section"] + "\t type: " + line["type"] + " \t string: " + line["string"])

            for function in functions.keys():
                self.log("Microphone detection found!  \n \t name: " + function + " vaddr: " + functions[function])
                if self.cfg:
                    self.log(self.funcCFG(function))
                if self.pdd:
                    self.log(self.funcPDD(function))
        except:
            raise R2Error("error microphone detection")

    def findHttp(self):
        try:
            if self.analyzed == False:
                self.autoAnalysis()

            functions = dict()
            noFunc = list()

            vendorSearch = self.findString("http:")
            if len(vendorSearch) == 0:
                return
            for line in vendorSearch:
                vaddr = line["vaddr"]
                rawXrefs = self.findXrefs(vaddr)
                if len(rawXrefs) == 0:
                    noFunc.append(line)
                    continue
                xrefs = self.parseXrefs(rawXrefs)
                for xref in xrefs:
                    if len(xref) <= 1:
                        continue
                    if xref[0] == "(nofunc)":
                        line["xref"] = xref[3]
                        noFunc.append(line)
                        continue
                    functions[xref[0]] = xref[1]

            if self.summary:
                if len(functions) == 0:
                    if len(noFunc) == 0:
                        self.summaryResults["Insecure URLs Found"] = False
                        return
                self.summaryResults["Insecure URLs Found"] = True
                return
            if len(functions) == 0:
                if len(noFunc) == 0:
                    self.log("No insecure URLs found!")
                else:
                    self.log("Evidence of insecure URLs found, however no function references can be automatically found!")
                    if len(noFunc) != 0:
                        for line in noFunc:
                            if "xref" in line.keys():
                                self.log("\t vaddr: " + line["vaddr"] + "\t xref: " + line["xref"] + " \t section: " + line["section"] + "\t type: " + line["type"] + " \t string: " + line["string"])
                            else:
                                self.log("\t vaddr: " + line["vaddr"] + " \t section: " + line["section"] + "\t type: " + line["type"] + " \t string: " + line["string"])

            for function in functions.keys():
                self.log("Insecure URLs found!  \n \t name: " + function + " vaddr: " + functions[function])
                if self.cfg:
                    self.log(self.funcCFG(function))
                if self.pdd:
                    self.log(self.funcPDD(function))
        except:
            raise R2Error("error insecure URL detection")

    def findCrypto(self):
        try:
            if self.analyzed == False:
                self.autoAnalysis()

            functions = list()
            noFunc = list()
            cryptoSearch = self.findCryptoKeys()
            if len(cryptoSearch) == 0:
                return
            for line in cryptoSearch:
                vaddr = line["vaddr"]
                rawXrefs = self.findXrefs(vaddr)
                if len(rawXrefs) == 0:
                    noFunc.append(line)
                    continue
                xrefs = self.parseXrefs(rawXrefs)
                for xref in xrefs:
                    if len(xref) <= 1:
                        continue
                    if xref[0] == "(nofunc)":
                        line["xref"] = xref[3]
                        noFunc.append(line)
                        continue

                    line["function"] = xref[0]
                    functions.append(line)

            if self.summary:
                if len(functions) == 0:
                    if len(noFunc) == 0:
                        self.summaryResults["Encryption Found"] = False
                        return
                self.summaryResults["Encryption Found"] = True
                return
            if len(noFunc) == 0:
                if len(functions) == 0:
                    self.log("No encryption functions found!")
            else:
                self.log("Encryption functions that can not be automatically xref'd to a function header: ")
                if len(noFunc) != 0:
                    for line in noFunc:
                        if "xref" in line.keys():
                            if "potentialKeys" in line.keys():
                                if len(line["potentialKeys"]) == 0:
                                    self.log("\t vaddr: " + line["vaddr"] + "\t xref: " + line["xref"] + " \t section: " + line["section"] + "\t type: " + line["type"] + " \t string: " + line["string"])
                                else:
                                    for key in line["potentialKeys"]:
                                        self.log("\t vaddr: " + line["vaddr"] + "\t xref: " + line["xref"] + " \t section: " + line["section"] + "\t type: " + line["type"] + " \t string: " + line["string"] + " \t algorithm: " + line["algorithm"] + " \t potentialKey/IV: " + key) 
                        else:
                            if len(line["potentialKeys"]) == 0:
                                    self.log("\t vaddr: " + line["vaddr"] + " \t section: " + line["section"] + "\t type: " + line["type"] + " \t string: " + line["string"])
                            else:
                                for key in line["potentialKeys"]:
                                    self.log("\t vaddr: " + line["vaddr"] + " \t section: " + line["section"] + "\t type: " + line["type"] + " \t string: " + line["string"] + " \t algorithm: " + line["algorithm"] + " \t potentialKey/IV: " + key)

            for function in functions:
                if len(line["potentialKeys"]) == 0:
                    for key in line["potentialKeys"]:
                        self.log("Encryption functions found!  \n \t name: " + function["function"]  + " \t vaddr: " + function["vaddr"] + " \t algorithm: " + line["algorithm"] + " \t potentialKey/IV: " + key)
                else:
                    self.log("Encryption functions found!  \n \t name: " + function["function"]  + " \t vaddr: " + function["vaddr"] + " \t algorithm: " + line["algorithm"])
                if self.cfg:
                    self.log(self.funcCFG(function["function"]))
                if self.pdd:
                    self.log(self.funcPDD(function["function"]))
        except:
            raise R2Error("error finding crypto functions")

    def liveMemory(self):
        try:
            if self.analyzed == False:
                self.autoAnalysis()
            output = self.runR2Cmd("doo; db main; dc")
            print(output)
        except:
            raise R2Error("error attaching debugger")
        
    def printSummary(self):
        self.summary = True
        self.findVMs()
        self.findCameraBindings()
        self.findMicrophoneBindings()
        self.findHttp()
        self.findCrypto()
        self.log("\t ---- Security/Privacy Feature Summary ---- ")
        for key in self.summaryResults.keys():
            if self.summaryResults[key] == True:
                self.log(key + ": \t \t " + u'\u2713')
            else:
                self.log(key + ": \t \t " + u'\u2717')

        self.summary = False

def main():
    args = parseArgs()
    EPR2 = ExamPaperR2(args.binary[0], args.cfg, args.pdd)
    EPR2.load()

    if args.liveMemory:
        liveMemoryConsent = input("WARNING!!! --liveMemory will run potentially untrusted code on the host system!  Continue (Y/n): ")
        if "Y" in liveMemoryConsent:
            EPR2.liveMemory()

    if args.summary:
        EPR2.printSummary()
        exit()

    if args.segments:
        print(EPR2.symbols())

    if args.vm:
        EPR2.findVMs()

    if args.webcam:
        EPR2.findCameraBindings()

    if args.microphone:
        EPR2.findMicrophoneBindings()

    if args.insecureHttp:
        EPR2.findHttp()

    if args.encryption:
        EPR2.findCrypto()

        
if __name__ == "__main__":
    main()
