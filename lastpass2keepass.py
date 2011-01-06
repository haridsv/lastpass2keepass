# lastpass2keepass
# Supports:
# Keepass XML - keepassxml
# USAGE: python lastpass2keepass.py exportedTextFile
# The LastPass Export format;
# url,username,password,1extra,name,grouping(\ delimited),last_touch,launch_count,fav

import sys, csv, time, datetime, itertools, re # Toolkit
import traceback
from datetime import datetime
import xml.etree.ElementTree as ET # Saves data, easier to type

# Strings

fileError = "You either need more permissions or the file does not exist."
lineBreak = "____________________________________________________________\n"

def formattedPrint(string):
    print lineBreak
    print string
    print lineBreak
       
# Files
# Check for existence/read/write.

try:
    inputFile = sys.argv[1]
except:
    formattedPrint("USAGE: python lastpass2keepass.py exportedTextFile")
    sys.exit()
    
try:
    f = open(inputFile)
except IOError:
    traceback.print_exc()
    formattedPrint("Cannot read file: '%s' Error: '%s'" % (inputFile, fileError) )
    sys.exit()

# Create XML file.
outputFile = inputFile + ".export.xml"

try:
    open(outputFile, "w").close() # Clean.
    w = open(outputFile, "w")
except IOError:
    traceback.print_exc()
    formattedPrint("Cannot write to disk... exiting. Error: '%s'" % (fileError) )
    sys.exit()

# Parser
# Parse w/ delimter being comma, and entries separted by newlines
reader = csv.reader(f, delimiter=',', quotechar='\n')

# Create a list of the entries, allow us to manipulate it.
# Can't be done with reader object.

allEntries = []

for x in reader:
    allEntries.append(x)

allEntries.pop(0) # Remove LP format string.

f.close() # Close the read file.

# Keepass XML generator
   
# Add doctype to head, clear file.
w.write('<?xml version="1.0" encoding="utf-8" standalone="yes"?>')

# Generate Creation date
# Form current time expression.
isoDtFormat = "%Y-%m-%dT%H:%M:%S"
lpDtFormat = "%Y-%m-%d %H:%M:%S"
now = datetime.now()
formattedNow = now.strftime(isoDtFormat)

# Initialize tree
# build a tree structure
page = ET.Element('pwlist')
doc = ET.ElementTree(page)

# Dictionary of failed entries
failed = {}
    
formattedPrint("DEBUG of '%s' file conversion to the KeePassXML format, outputing to the '%s' file." %(inputFile,outputFile))
    
# A dictionary, organising the categories.
for entry in allEntries:
    try:
        # Each entryElement
        entryElement = ET.SubElement(page, "pwentry")
        # entryElement tree
        grouping = re.split(r"[/\\]",entry[5])
        ET.SubElement(entryElement, 'group', tree="LastPass").text = grouping and grouping[0] or "(none)"
        ET.SubElement(entryElement, 'title').text = str(entry[4])
        ET.SubElement(entryElement, 'username').text = str(entry[1])
        ET.SubElement(entryElement, 'password').text = str(entry[2])
        ET.SubElement(entryElement, 'url').text = str(entry[0])
        ET.SubElement(entryElement, 'notes').text = str(entry[3])
        ET.SubElement(entryElement, 'icon').text = "0"
        ET.SubElement(entryElement, 'creationtime').text = formattedNow
        try:
            lastAccTime = datetime.strptime(entry[6], lpDtFormat).strftime(isoDtFormat)
        except ValueError:
            lastAccTime = formattedNow
        ET.SubElement(entryElement, 'lastaccesstime').text = lastAccTime
        ET.SubElement(entryElement, 'expiretime', expires="false").text = "2999-12-28T23:59:59"
    except Exception, e:
        # Catch illformed entries          
        # Grab entry position
        p = allEntries.index(entry) + 2
        failed[p] = [",".join(entry)]
        print "Failed to format entry at line %d, due to error: %s" % (p, ' '.join(e.args))

# Check if it was a clean conversion.
if len(failed) != 0:
    # Create a failed list.
    failedList = ["%d : %s" %(p, str(e[0]).decode("utf-8")) for p, e in failed.items()]
    formattedPrint("The conversion was not clean.")
    print "You need to manually import the below entries from the '%s' file, as listed by below." %(inputFile)
    formattedPrint("Line Number : entryElement")
    for x in failedList:
        print x

# Write out tree
# wrap it in an ElementTree instance, and save as XML
doc.write(w, encoding="utf-8")
w.close()

print lineBreak
print "\n'%s' has been succesfully converted to the KeePassXML format." %(inputFile)
print "Converted data can be found in the '%s' file.\n" %(outputFile)
print lineBreak
